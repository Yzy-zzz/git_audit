# 在 GitLab 服务器上启用“全局 Server Hook”

实现三件事：

1) 只扫描**代码注释**里的敏感词  
2) 扫描 **commit message** 的敏感词  
3) **禁止特定扩展名**（如 `.docx|.zip|.gz|…`）被推送

> 下面步骤适用于 **自建 GitLab（Self-Managed）**。GitLab 官方支持全局 server hooks，并建议在 **Gitaly** 的 `custom_hooks_dir` 下创建 `pre-receive.d` 目录，按文件名字母序执行其中脚本；自定义错误信息加前缀 **`GL-HOOK-ERR:`** 可在 GitLab UI 中显示。([GitLab Docs](https://docs.gitlab.com/administration/server_hooks/))

1. **确认/设置全局 hooks 目录**（Omnibus 安装）  
   编辑 `/etc/gitlab/gitlab.rb`，确保有（或取消注释）：

   ```ruby
   gitaly['configuration'] = {
     hooks: { custom_hooks_dir: "/var/opt/gitlab/gitaly/custom_hooks" }
   }
   ```

2. **创建 pre-receive 脚本目录并放置脚本**  

   ```
   sudo mkdir -p /var/opt/gitlab/gitaly/custom_hooks/pre-receive.d/
   ```

3. 脚本内容如下，文件名**policy-checks** (无需后缀)

   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   LC_ALL=C
   
   # ========= 可配置区域（也可通过外部策略文件覆盖，见注释） =========
   # 1) 敏感词（用于 commit message 与注释行）
   #    - 默认：常见中英文关键词 + 常见 AKIA/私钥头
   DEFAULT_SENSITIVE_PATTERN='密钥|密码|口令|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
   
   # 2) 禁止的扩展名（正则，结尾匹配）
   DEFAULT_DENY_EXT_REGEX='\.((docx)|(zip)|(gz)|(7z)|(rar)|(tar)|(tgz)|(jar)|(war))$'
   
   # 3) 注释行识别（针对“新增的行”）
   #    识别常见注释前缀：#, //, /*, *, --, ;, <!--, """ , '''
   COMMENT_PREFIX_REGEX='^\+\s*(#|//|/\*|\*|--|;|<!--|"""|'"'"'""|'"'"')'
   
   # 4) 可选的策略文件（若存在则覆盖默认）
   POLICY_DIR="/etc/gitlab/push-policy"
   KEYWORDS_FILE="${POLICY_DIR}/sensitive_keywords.txt"   # 每行一个正则/词；自动 -f 读入
   DENY_EXT_FILE="${POLICY_DIR}/deny_extensions.txt"       # 每行一个扩展名（不带点），自动拼成正则
   PATH_IGNORE_FILE="${POLICY_DIR}/path_ignore_globs.txt"  # 每行一个glob，匹配则跳过扫描（如 vendor/**）
   
   # ========= 内部函数 =========
   die() { echo "GL-HOOK-ERR: $*" >&2; exit 1; }
   
   build_deny_ext_regex() {
     if [[ -s "$DENY_EXT_FILE" ]]; then
       local joined ext
       joined="$(tr -s '\r\n' '\n' <"$DENY_EXT_FILE" | grep -Ev '^\s*(#|$)' | paste -sd'|' -)"
       [[ -n "${joined:-}" ]] && echo "\\.(${joined})$" || echo "$DEFAULT_DENY_EXT_REGEX"
     else
       echo "$DEFAULT_DENY_EXT_REGEX"
     fi
   }
   
   path_ignored() {
     local p="$1"
     [[ -s "$PATH_IGNORE_FILE" ]] || return 1
     while IFS= read -r pattern; do
       [[ -z "$pattern" || "$pattern" =~ ^\s*# ]] && continue
       # 使用bash的glob匹配
       if [[ "$p" == $pattern ]]; then return 0; fi
     done < <(tr -d '\r' < "$PATH_IGNORE_FILE")
     return 1
   }
   
   grep_sensitive() {
     # 使用文件列表或默认模式匹配（忽略大小写）
     if [[ -s "$KEYWORDS_FILE" ]]; then
       grep -Ei -f "$KEYWORDS_FILE"
     else
       grep -Ei "$DEFAULT_SENSITIVE_PATTERN"
     fi
   }
   
   check_commit_message() {
     local commit="$1" msg
     msg="$(git log -1 --pretty=%B "$commit")" || return 0
     if printf '%s' "$msg" | grep_sensitive >/dev/null; then
       die "提交信息包含敏感词（commit: $commit）"
     fi
   }
   
   deny_extensions() {
     local path="$1" regex="$2"
     if echo "$path" | grep -Eq "$regex"; then
       die "禁止提交此类文件：$path"
     fi
   }
   
   scan_added_comment_lines() {
     local commit="$1" path="$2"
     # 仅看“新增的行”，并过滤出“看起来是注释的新增行”
     # 排除 diff 头部的 '+++'
     if git diff -U0 "${commit}^" "$commit" -- "$path" \
         | grep -E '^\+[^+]' \
         | grep -E "$COMMENT_PREFIX_REGEX" \
         | sed -E 's/^\+//' \
         | grep_sensitive >/dev/null; then
       die "在注释中发现敏感词：$path @ $commit"
     fi
   }
   
   check_commit() {
     local commit="$1" deny_ext_regex="$2"
     # 1) commit message
     check_commit_message "$commit"
   
     # 2) 遍历该 commit 的变更文件（新增/修改/复制/重命名）
     while IFS= read -r path; do
       [[ -z "$path" ]] && continue
       # 忽略某些路径（如果配置了）
       if path_ignored "$path"; then
         continue
       fi
       # 2.1 扩展名黑名单
       deny_extensions "$path" "$deny_ext_regex"
   
       # 2.2 仅扫描文本文件的“新增注释行”
       #     - 二进制diff不会出现以'+'开头的内容行；这里按新增行+注释前缀筛选
       scan_added_comment_lines "$commit" "$path"
     done < <(git diff-tree --no-commit-id --name-only -r --diff-filter=ACMR "$commit")
   }
   
   # ========= 主逻辑 =========
   DENY_EXT_REGEX="$(build_deny_ext_regex)"
   
   # 读取 stdin 的多行: oldrev newrev refname
   while read -r oldrev newrev refname; do
     # 分支删除（newrev 为 000...）不处理
     if [[ "$newrev" =~ ^0{40}$ ]]; then
       continue
     fi
     # 遍历此次 push 引入的所有非合并提交
     while read -r commit; do
       check_commit "$commit" "$DENY_EXT_REGEX"
     done < <(git rev-list --no-merges "${oldrev}..${newrev}")
   done
   
   exit 0
   ```

   - **为何是 `pre-receive.d/`？** GitLab 支持把同类 hook 放到 `*.d/` 目录下，所有可执行文件按**字母序**执行，任一非零退出会**阻断 push**。([GitLab Docs](https://docs.gitlab.com/administration/server_hooks/))  
   - **为何 `GL-HOOK-ERR:`？** 该前缀的输出会在 UI 中展示给用户，便于准确提示被拒绝原因。([GitLab Docs](https://docs.gitlab.com/administration/server_hooks/))

4. 将脚本变为可执行状态

   ```bash
   sudo chmod +x /var/opt/gitlab/gitaly/custom_hooks/pre-receive.d/policy-checks
   ```

5. **应用配置**

   ```bash
   sudo gitlab-ctl reconfigure
   ```

6. **（可选）集中化策略文件**  
   若你想不用改脚本就能调整规则，新建目录并按需填入三类可选配置：

   ```bash
   sudo mkdir -p /etc/gitlab/push-policy
   # 1) 追加或覆盖敏感词（正则或纯词，每行一条）
   sudo tee /etc/gitlab/push-policy/sensitive_keywords.txt >/dev/null <<'EOF'
   (密钥|密码|口令)
   (?i)\b(secret|token|apikey|api[_-]?key|private[_-]?key)\b
   AKIA[0-9A-Z]{16}
   -----BEGIN [A-Z ]*PRIVATE KEY-----
   EOF
   
   # 2) 追加/覆盖禁止扩展名（不带点，每行一个）
   sudo tee /etc/gitlab/push-policy/deny_extensions.txt >/dev/null <<'EOF'
   docx
   zip
   gz
   7z
   rar
   tar
   tgz
   jar
   war
   EOF
   
   # 3) （可选）忽略不需要扫描的路径（glob）
   sudo tee /etc/gitlab/push-policy/path_ignore_globs.txt >/dev/null <<'EOF'
   vendor/**
   third_party/**
   EOF
   ```
   > 脚本会自动读取这些文件并生效，无需重启。  

---

# 脚本细节与实现要点

- **扫描范围**  
  - **Commit message**：完整正文，用敏感词正则匹配（忽略大小写）。  
  - **代码注释**：仅扫描“新增的行”，并仅在**注释前缀**（如 `# // /* * -- ; <!-- """ '''`）的新增行里做关键词匹配，减少误报与性能开销。  
  - **扩展名黑名单**：对所有变更文件名进行结尾匹配，命中即拒绝。

- **为什么选择 pre-receive？**  
  pre-receive 在**服务器入库前**拦截，能直接阻断 push；GitLab 官方支持以 **`custom_hooks_dir`** 作为**全局**生效目录，且允许多个脚本链式执行。([GitLab Docs](https://docs.gitlab.com/administration/server_hooks/))

- **错误提示**  
  所有拒绝原因统一通过 `GL-HOOK-ERR:` 前缀返回，在 UI 和 `git push` 输出里清晰可见。([GitLab Docs](https://docs.gitlab.com/administration/server_hooks/))

---

# 测试方法（本地即可验证）

1) **禁止扩展名**  
   ```bash
   echo "dummy" > secret.docx
   git add secret.docx
   git commit -m "add docx"
   git push  # 预期：被拒绝，提示“禁止提交此类文件”
   ```

2) **commit message 敏感词**  
   ```bash
   echo "ok" > ok.txt && git add ok.txt
   git commit -m "leak: this has secret token"
   git push  # 预期：被拒绝，提示“提交信息包含敏感词”
   ```

3) **注释中的敏感词**（只拦“注释行”）  
   ```bash
   cat > demo.py <<'PY'
   # TODO: do not hardcode password
   x = 1  # 正常注释
   PY
   git add demo.py && git commit -m "test comment"
   git push  # 预期：被拒绝，提示“在注释中发现敏感词”
   ```


#!/usr/bin/env python3

import os, csv, re, sys, subprocess, json
from typing import List, Dict, Tuple

# === 敏感词和扩展名配置（与你原来的保持一致） ===
def parse_sensitive_words():
    raw_words = os.environ.get("SENSITIVE_WORDS", "")
    if raw_words.strip():
        words = [w.strip() for w in raw_words.split(",") if w.strip()]
    else:
        words = ["secret","password","regex:\\bGK\\b",
                 "access_key","api_key","client_secret","credential","confidential","regex:.*ok.*"]
    
    patterns = []
    word_list = []
    
    for word in words:
        if word.startswith("regex:"):
            regex_pattern = word[6:]
            try:
                patterns.append(re.compile(regex_pattern, re.IGNORECASE | re.ASCII))
                word_list.append(f"regex:{regex_pattern}")
            except re.error as e:
                print(f"警告：无效的正则表达式 '{regex_pattern}': {e}", file=sys.stderr)
                patterns.append(re.compile(re.escape(regex_pattern), re.IGNORECASE))
                word_list.append(regex_pattern)
        else:
            patterns.append(re.compile(re.escape(word), re.IGNORECASE))
            word_list.append(word)
    
    return patterns, word_list

WORD_PATTERNS, WORDS = parse_sensitive_words()

C_LIKE = {"c","h","hpp","hh","cpp","cc","cxx","java","js","jsx","ts","tsx","go","php","kt","kts","scala","rs","swift","css","scss"}
HASH_LIKE = {"py","rb","sh","bash","zsh","pl","pm","ps1","psm1","yml","yaml","toml","ini","properties","tf","dockerfile","makefile"}
SQL_LIKE  = {"sql"}
OTHER_TEXT = {"md","txt","rst"}
CODE_EXTS = C_LIKE | HASH_LIKE | SQL_LIKE | OTHER_TEXT
BINARY_EXTS = {".zip", ".doc", ".docx", ".txt", ".gz", ".tar", ".rar", ".7z", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx"}
SKIP_DIRS = {".git","node_modules","vendor","dist","build",".next",".venv","venv","target","out","bin","obj"}
MAX_BYTES = 1_000_000

# === 核心替换：使用 gitlab-rails 获取项目物理路径 ===
def get_project_mappings() -> List[Dict]:
    print("正在从 GitLab 数据库提取项目物理路径（启动 Rails 环境可能需要 15-30 秒）...")
    # 这段 Ruby 代码将在 GitLab 环境内执行，直接读取数据库并返回 JSON
    ruby_script = """
    require 'json'
    projects = Project.where.not(pending_delete: true).map do |p|
      next if p.empty_repo?
      {
        id: p.id,
        name: p.full_path,
        branch: p.default_branch || 'master',
        repo_path: p.repository.path_to_repo
      }
    end.compact
    puts "===JSON_START==="
    puts projects.to_json
    puts "===JSON_END==="
    """
    
    cmd = ['gitlab-rails', 'runner', ruby_script]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    
    if result.returncode != 0:
        print(f"获取路径失败:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    # 解析输出中的 JSON
    json_str = ""
    in_json = False
    for line in result.stdout.splitlines():
        if line == "===JSON_START===":
            in_json = True
            continue
        if line == "===JSON_END===":
            break
        if in_json:
            json_str += line
            
    return json.loads(json_str)

# === 本地 Git 命令封装 ===
def ext_of(path: str) -> str:
    fn = path.lower()
    if fn.endswith("dockerfile"): return "dockerfile"
    i = fn.rfind(".")
    return fn[i+1:] if i != -1 else ""

def in_skip_dir(path: str) -> bool:
    parts = path.split("/")
    return any(part.lower() in SKIP_DIRS for part in parts[:-1])

def is_text(b: bytes) -> bool:
    return b"\x00" not in b[:1024]

def list_tree_local(repo_path: str):
    """利用本地 git ls-tree 快速列出所有文件"""
    cmd = ['git', '--git-dir', repo_path, 'ls-tree', '-r', 'HEAD']
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode != 0:
        return []
    
    files = []
    for line in result.stdout.splitlines():
        # 输出格式: 100644 blob hash\tpath/to/file
        parts = line.split('\t', 1)
        if len(parts) == 2:
            files.append(parts[1])
    return files

def fetch_raw_local(repo_path: str, file_path: str) -> bytes:
    """利用本地 git show 读取文件内容，瞬间返回，无需 HTTP"""
    cmd = ['git', '--git-dir', repo_path, 'show', f'HEAD:{file_path}']
    # 因为要读取二进制片段检查，所以不使用 text=True
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout[:MAX_BYTES]

def scan_comment_lines(ext: str, text: str) -> List[Tuple[int, str, str]]:
    # （逻辑与你原版保持完全一致，此处省略修改，直接复用你原有的解析逻辑）
    hits = []
    lines = text.splitlines()
    in_block = False

    for idx, line in enumerate(lines, 1):
        s = line.lstrip()
        comment_segment = None

        if ext in HASH_LIKE:
            if s.startswith("#"): comment_segment = s[1:]
        if ext in SQL_LIKE:
            if s.startswith("--"): comment_segment = s[2:]
            if "/*" in s and "*/" in s: comment_segment = s[s.find("/*")+2:s.rfind("*/")]
            elif "/*" in s:
                in_block = True
                comment_segment = s[s.find("/*")+2:]
            elif "*/" in s and in_block:
                comment_segment = s[:s.find("*/")]
                in_block = False
            elif in_block: comment_segment = s
        if ext in C_LIKE:
            if "//" in s: comment_segment = s[s.find("//")+2:]
            if "/*" in s and "*/" in s: comment_segment = (comment_segment or "") + " " + s[s.find("/*")+2:s.rfind("*/")]
            elif "/*" in s:
                in_block = True
                comment_segment = (comment_segment or "") + " " + s[s.find("/*")+2:]
            elif "*/" in s and in_block:
                comment_segment = (comment_segment or "") + " " + s[:s.find("*/")]
                in_block = False
            elif in_block and comment_segment is None:
                comment_segment = s
        if ext in OTHER_TEXT and comment_segment is None:
            comment_segment = s

        if comment_segment:
            seg = comment_segment.strip()
            if not seg: continue
            for i, pat in enumerate(WORD_PATTERNS):
                if pat.search(seg):
                    excerpt = seg[:240]
                    matched_word = WORDS[i]
                    hits.append((idx, matched_word, excerpt))
                    break
    return hits

def get_commits_local(repo_path: str) -> List[Dict]:
    """利用本地 git log 获取 commit 历史，速度极快"""
    # 格式：Hash|Author|Date|Message，使用特殊分隔符避免消息内换行导致解析错误
    delimiter = "|||COMMIT_SEP|||"
    cmd = ['git', '--git-dir', repo_path, 'log', 'HEAD', '-1000', f'--pretty=format:%H|%an|%cI|%B{delimiter}']
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode != 0:
        return []
    
    commits = []
    raw_logs = result.stdout.split(delimiter)
    for log in raw_logs:
        if not log.strip(): continue
        parts = log.strip().split('|', 3)
        if len(parts) == 4:
            commits.append({
                "id": parts[0],
                "author_name": parts[1],
                "created_at": parts[2],
                "message": parts[3]
            })
    return commits

def scan_commit_message(message: str) -> List[str]:
    hits = []
    if not message: return hits
    for i, pat in enumerate(WORD_PATTERNS):
        if pat.search(message):
            hits.append(WORDS[i])
    return list(set(hits))

# === 初始化 CSV 相关函数 ===
def init_csv_files():
    with open("binary_hits.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["project_id","project","branch","file_path"])
    with open("comment_hits.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["project_id","project","branch","file_path","line","keyword","comment_excerpt"])
    with open("commit_hits.csv", "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["project_id","project","commit_id","commit_message","author","date","keyword","message_excerpt"])

def append_to_csv(filename, rows):
    if not rows: return
    with open(filename, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)

# === 主流程 ===
def main():
    init_csv_files()
    
    projects = get_project_mappings()
    total_projects = len(projects)
    print(f"成功获取 {total_projects} 个非空项目的物理路径，开始本地极速扫描...")
    
    total_binary_hits = 0
    total_comment_hits = 0
    total_commit_hits = 0
    
    for idx, p in enumerate(projects, 1):
        pid = p["id"]
        full = p["name"]
        ref = p["branch"]
        repo_path = p["repo_path"]
        
        print(f"[{idx}/{total_projects}] 正在扫描项目: {full}")
        
        # 物理路径可能不存在（例如尚未初始化的裸库）
        if not os.path.exists(repo_path):
            print(f"  [跳过] 找不到物理路径: {repo_path}")
            continue

        project_bin_rows, project_comment_rows, project_commit_rows = [], [], []

        # 1 & 2. 扫描文件系统
        files = list_tree_local(repo_path)
        for path in files:
            if in_skip_dir(path): continue
            
            low = path.lower()
            if any(low.endswith(ext) for ext in BINARY_EXTS):
                project_bin_rows.append([pid, full, ref, path])
                continue

            ext = ext_of(path)
            if ext not in CODE_EXTS: continue

            raw = fetch_raw_local(repo_path, path)
            if not raw or not is_text(raw): continue

            try:
                text = raw.decode("utf-8", errors="ignore")
                hits = scan_comment_lines(ext, text)
                for (lineno, matched_word, excerpt) in hits:
                    project_comment_rows.append([pid, full, ref, path, lineno, matched_word, excerpt])
            except Exception:
                continue

        # 3. 扫描 Commit 历史
        commits = get_commits_local(repo_path)
        for commit in commits:
            msg = commit["message"]
            keywords = scan_commit_message(msg)
            for keyword in keywords:
                excerpt = msg.replace('\n', ' ').replace('\r', ' ')[:200]
                project_commit_rows.append([
                    pid, full, commit["id"][:8], excerpt, 
                    commit["author_name"], commit["created_at"], keyword, msg[:240]
                ])

        # 写入结果
        append_to_csv("binary_hits.csv", project_bin_rows)
        append_to_csv("comment_hits.csv", project_comment_rows)
        append_to_csv("commit_hits.csv", project_commit_rows)
        
        total_binary_hits += len(project_bin_rows)
        total_comment_hits += len(project_comment_rows)
        total_commit_hits += len(project_commit_rows)
        
        if project_bin_rows or project_comment_rows or project_commit_rows:
            print(f"  -> 发现: 二进制 {len(project_bin_rows)} 个, 敏感注释 {len(project_comment_rows)} 条, 敏感commit {len(project_commit_rows)} 条")
        else:
            print(f"  -> 无发现")

    print(f"\n扫描完成！")
    print(f"总计发现二进制文件：{total_binary_hits} 条")
    print(f"总计发现注释敏感词：{total_comment_hits} 条")
    print(f"总计发现commit敏感词：{total_commit_hits} 条")

if __name__ == "__main__":
    main()
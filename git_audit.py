#!/usr/bin/env python3

# 三个功能：
# 1. 扫描 GitLab 上的所有项目，找出提交的二进制文件（如 .zip, .doc 等）
# 2. 扫描代码注释，找出包含敏感词的注释行（如密码、密钥等）
# 3. 扫描每个项目的commit历史信息，找出包含敏感词的提交记录

# 可配置项：
# - GITLAB_URL: GitLab 实例地址，如 https://gitlab.com 或 http://10.26.31.128:80
# - GITLAB_TOKEN: 访问令牌，需有读取项目权限

import os, csv, re, time, sys, urllib.parse, requests
from typing import List, Dict, Tuple

# BASE = os.environ.get("GITLAB_URL", "").rstrip("/")
BASE = "http://10.26.31.128:80"  # 自建 GitLab 请设置环境变量 GITLAB_URL
# TOKEN = os.environ.get("GITLAB_TOKEN")
# token 需要有读取项目权限，在 GitLab 个人设置页面生成
TOKEN = ""

if not BASE or not TOKEN:
    print("请先设置环境变量 GITLAB_URL 和 GITLAB_TOKEN", file=sys.stderr); sys.exit(1)

HEADERS = {
    "PRIVATE-TOKEN": TOKEN,              # 自建 GitLab 常用
    "Authorization": f"Bearer {TOKEN}",  # 兼容 Bearer
}

# 你可以通过环境变量自定义敏感词；支持正则表达式和普通字符串混合（中英文）
# 格式：SENSITIVE_WORDS="密码,secret,regex:(?:api[_-]?key|access[_-]?token)"
# 使用 "regex:" 前缀表示正则表达式，其他为普通字符串
def parse_sensitive_words():
    """解析敏感词配置，支持正则表达式和普通字符串混合"""
    raw_words = os.environ.get("SENSITIVE_WORDS", "")
    if raw_words.strip():
        words = [w.strip() for w in raw_words.split(",") if w.strip()]
    else:
        words = ["secret","password",
                 "access_key","api_key","client_secret","credential","confidential","regex:.*ok.*"]
    
    patterns = []
    word_list = []  # 用于记录原始词汇（用于报告）
    
    for word in words:
        if word.startswith("regex:"):
            # 正则表达式模式
            regex_pattern = word[6:]  # 去掉 "regex:" 前缀
            try:
                patterns.append(re.compile(regex_pattern, re.IGNORECASE))
                word_list.append(f"regex:{regex_pattern}")
            except re.error as e:
                print(f"警告：无效的正则表达式 '{regex_pattern}': {e}", file=sys.stderr)
                # 如果正则无效，按普通字符串处理
                patterns.append(re.compile(re.escape(regex_pattern), re.IGNORECASE))
                word_list.append(regex_pattern)
        else:
            # 普通字符串，需要转义
            patterns.append(re.compile(re.escape(word), re.IGNORECASE))
            word_list.append(word)
    
    return patterns, word_list

# 解析敏感词配置
WORD_PATTERNS, WORDS = parse_sensitive_words()

# 需要扫描注释的代码扩展名（可按需扩充）
C_LIKE = {"c","h","hpp","hh","cpp","cc","cxx","java","js","jsx","ts","tsx","go","php","kt","kts","scala","rs","swift","css","scss"}
HASH_LIKE = {"py","rb","sh","bash","zsh","pl","pm","ps1","psm1","yml","yaml","toml","ini","properties","tf","dockerfile","makefile"}
SQL_LIKE  = {"sql"}
OTHER_TEXT = {"md","txt","rst"}  # 可选：若也想扫文档里的注释/说明

CODE_EXTS = C_LIKE | HASH_LIKE | SQL_LIKE | OTHER_TEXT

# 需要单独处理的二进制/压缩文件后缀
BINARY_EXTS = {".zip", ".doc", ".docx", ".txt", ".gz", ".tar", ".rar", ".7z", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx"}

SKIP_DIRS = {".git","node_modules","vendor","dist","build",".next",".venv","venv","target","out","bin","obj"}
MAX_BYTES = 1_000_000  # 单文件最多读取 1MB，避免撑爆/扫二进制

def get(url, params=None, stream=False):
    for _ in range(3):
        r = requests.get(url, headers=HEADERS, params=params, timeout=60, stream=stream)
        if r.status_code in (200, 201):
            return r
        if r.status_code == 429:
            time.sleep(2); continue
        if r.status_code >= 500:
            time.sleep(2); continue
        r.raise_for_status()
    r.raise_for_status()

def iter_projects():
    """获取所有项目，同时返回项目总数用于进度条"""
    projects = []
    page = 1
    while True:
        r = get(f"{BASE}/api/v4/projects", params={
            "per_page": 100, "page": page, "simple": True, "archived": False,
            "order_by": "id", "sort": "asc", "membership": False
        })
        items = r.json()
        if not items: break
        projects.extend(items)
        page += 1
    return projects

def list_tree(proj_id: int, ref: str):
    page = 1
    while True:
        r = get(f"{BASE}/api/v4/projects/{proj_id}/repository/tree", params={
            "ref": ref, "recursive": True, "per_page": 100, "page": page
        })
        arr = r.json()
        if not arr: break
        for it in arr:
            yield it  # {id,name,type,path,mode}
        page += 1

def fetch_raw(proj_id: int, path: str, ref: str) -> bytes:
    enc = urllib.parse.quote_plus(path)
    url = f"{BASE}/api/v4/projects/{proj_id}/repository/files/{enc}/raw"
    r = get(url, params={"ref": ref}, stream=True)
    # 仅读前 MAX_BYTES
    data = b""
    for chunk in r.iter_content(chunk_size=8192):
        data += chunk
        if len(data) > MAX_BYTES:
            break
    return data

def is_text(b: bytes) -> bool:
    # 简单启发：若含大量 NUL 则视为二进制
    if b"\x00" in b[:1024]:
        return False
    return True

def ext_of(path: str) -> str:
    fn = path.lower()
    if fn.endswith("dockerfile"): return "dockerfile"
    i = fn.rfind(".")
    return fn[i+1:] if i != -1 else ""

def in_skip_dir(path: str) -> bool:
    parts = path.split("/")
    return any(part.lower() in SKIP_DIRS for part in parts[:-1])

def scan_comment_lines(ext: str, text: str) -> List[Tuple[int, str, str]]:
    hits = []
    lines = text.splitlines()
    in_block = False

    for idx, line in enumerate(lines, 1):
        s = line.lstrip()

        comment_segment = None

        if ext in HASH_LIKE:
            if s.startswith("#"):
                comment_segment = s[1:]

        if ext in SQL_LIKE:
            if s.startswith("--"):
                comment_segment = s[2:]
            # SQL 也支持 /* */ 块注释
            if "/*" in s and "*/" in s:
                comment_segment = s[s.find("/*")+2:s.rfind("*/")]
            elif "/*" in s:
                in_block = True
                comment_segment = s[s.find("/*")+2:]
            elif "*/" in s and in_block:
                comment_segment = s[:s.find("*/")]
                in_block = False
            elif in_block:
                comment_segment = s

        if ext in C_LIKE:
            if "//" in s:
                comment_segment = s[s.find("//")+2:]
            if "/*" in s and "*/" in s:
                comment_segment = (comment_segment or "") + " " + s[s.find("/*")+2:s.rfind("*/")]
            elif "/*" in s:
                in_block = True
                comment_segment = (comment_segment or "") + " " + s[s.find("/*")+2:]
            elif "*/" in s and in_block:
                comment_segment = (comment_segment or "") + " " + s[:s.find("*/")]
                in_block = False
            elif in_block and comment_segment is None:
                comment_segment = s

        # 其他文本：把整行当描述/注释处理（可按需关闭）
        if ext in OTHER_TEXT and comment_segment is None:
            comment_segment = s

        if comment_segment:
            seg = comment_segment.strip()
            if not seg: 
                continue
            for i, pat in enumerate(WORD_PATTERNS):
                if pat.search(seg):
                    # 收敛一下行内容，避免 CSV 太长
                    excerpt = seg[:240]
                    # 获取对应的原始词汇用于报告
                    matched_word = WORDS[i]
                    hits.append((idx, matched_word, excerpt))
                    break

    return hits

def get_commits(proj_id: int, ref: str = None) -> List[Dict]:
    """获取项目的commit历史"""
    commits = []
    page = 1
    params = {"per_page": 100, "page": page}
    if ref:
        params["ref_name"] = ref
    
    try:
        while True:
            r = get(f"{BASE}/api/v4/projects/{proj_id}/repository/commits", params=params)
            items = r.json()
            if not items:
                break
            commits.extend(items)
            page += 1
            params["page"] = page
            # 限制获取的commit数量，避免API超时
            if len(commits) >= 1000:
                break
    except Exception as e:
        print(f"    [警告] 获取commit历史失败: {e}")
    
    return commits

def scan_commit_message(message: str) -> List[str]:
    """扫描commit message中的敏感词"""
    hits = []
    if not message:
        return hits
    
    for i, pat in enumerate(WORD_PATTERNS):
        if pat.search(message):
            # 获取对应的原始词汇用于报告
            matched_word = WORDS[i]
            hits.append(matched_word)
    
    return list(set(hits))  # 去重

def init_csv_files():
    """初始化CSV文件，写入表头"""
    # 初始化二进制文件CSV
    with open("binary_hits.csv", "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(["project_id","project","branch","file_path"])
    
    # 初始化注释敏感词CSV
    with open("comment_hits.csv", "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(["project_id","project","branch","file_path","line","keyword","comment_excerpt"])
    
    # 初始化commit历史敏感词CSV
    with open("commit_hits.csv", "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(["project_id","project","commit_id","commit_message","author","date","keyword","message_excerpt"])

def append_to_binary_csv(rows):
    """追加二进制文件记录到CSV"""
    if not rows:
        return
    with open("binary_hits.csv", "a", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerows(rows)

def append_to_comment_csv(rows):
    """追加注释敏感词记录到CSV"""
    if not rows:
        return
    with open("comment_hits.csv", "a", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerows(rows)

def append_to_commit_csv(rows):
    """追加commit历史敏感词记录到CSV"""
    if not rows:
        return
    with open("commit_hits.csv", "a", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerows(rows)

def main():
    # 初始化CSV文件
    init_csv_files()
    
    # 获取所有项目
    print("正在获取项目列表...")
    projects = iter_projects()
    total_projects = len(projects)
    print(f"找到 {total_projects} 个项目，开始扫描...")
    
    total_binary_hits = 0
    total_comment_hits = 0
    total_commit_hits = 0
    
    # 逐个处理项目并显示进度
    for idx, p in enumerate(projects, 1):
        pid = p["id"]
        full = p.get("path_with_namespace") or p.get("name")
        ref = p.get("default_branch") or "main"
        
        # 显示当前进度
        print(f"[{idx}/{total_projects}] 正在扫描项目: {full}")
        
        # 如果没有默认分支，尝试 master；再不行就跳过
        if not ref:
            ref = "main"
        try_master = False
        try:
            tree = list(list_tree(pid, ref))
        except Exception:
            try_master = True
            tree = []
        if try_master:
            ref = "master"
            try:
                tree = list(list_tree(pid, ref))
            except Exception:
                print(f"  [跳过] {full}: 无默认分支/无法读取树")
                continue

        # 当前项目的记录
        project_bin_rows = []
        project_comment_rows = []
        project_commit_rows = []

        for node in tree:
            if node.get("type") != "blob":
                continue
            path = node["path"]
            if in_skip_dir(path):
                continue

            low = path.lower()
            # 检查是否为二进制文件
            if any(low.endswith(ext) for ext in BINARY_EXTS):
                project_bin_rows.append([pid, full, ref, path])
                continue

            ext = ext_of(path)
            if ext not in CODE_EXTS:
                continue

            try:
                raw = fetch_raw(pid, path, ref)
            except Exception:
                continue
            if not raw or not is_text(raw):
                continue

            try:
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            hits = scan_comment_lines(ext, text)
            for (lineno, matched_word, excerpt) in hits:
                project_comment_rows.append([pid, full, ref, path, lineno, matched_word, excerpt])

        # 扫描commit历史
        commits = get_commits(pid, ref)
        for commit in commits:
            commit_id = commit.get("id", "")
            commit_message = commit.get("message", "")
            author_name = commit.get("author_name", "")
            commit_date = commit.get("created_at", "")
            
            sensitive_words = scan_commit_message(commit_message)
            for keyword in sensitive_words:
                # 截取commit message片段，避免CSV过长
                message_excerpt = commit_message.replace('\n', ' ').replace('\r', ' ')[:200]
                project_commit_rows.append([
                    pid, full, commit_id[:8], message_excerpt, 
                    author_name, commit_date, keyword, commit_message[:240]
                ])

        # 每处理完一个项目就写入CSV
        append_to_binary_csv(project_bin_rows)
        append_to_comment_csv(project_comment_rows)
        append_to_commit_csv(project_commit_rows)
        
        # 更新统计并显示当前项目结果
        total_binary_hits += len(project_bin_rows)
        total_comment_hits += len(project_comment_rows)
        total_commit_hits += len(project_commit_rows)
        
        if project_bin_rows or project_comment_rows or project_commit_rows:
            print(f"  -> 发现: 二进制文件 {len(project_bin_rows)} 个, 敏感注释 {len(project_comment_rows)} 条, 敏感commit {len(project_commit_rows)} 条")
        else:
            print(f"  -> 无发现")
        
        # 对 API 客气一点
        time.sleep(0.1)

    print(f"\n扫描完成！")
    print(f"总计发现二进制文件：{total_binary_hits} 条")
    print(f"总计发现注释敏感词：{total_comment_hits} 条")
    print(f"总计发现commit敏感词：{total_commit_hits} 条")
    print("结果文件：binary_hits.csv, comment_hits.csv, commit_hits.csv")

if __name__ == "__main__":
    main()
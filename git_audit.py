#!/usr/bin/env python3

# 两个功能：
# 1. 扫描 GitLab 上的所有项目，找出提交的二进制文件（如 .zip, .doc 等）
# 2. 扫描代码注释，找出包含敏感词的注释行（如密码、密钥等）

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

# 你可以通过环境变量自定义敏感词；默认提供一份通用清单（中英文）
raw_words = os.environ.get("SENSITIVE_WORDS", "")
if raw_words.strip():
    WORDS = [w.strip() for w in raw_words.split(",") if w.strip()]
else:
    WORDS = ["密码","密钥","私钥","机密","仅限内部","敏感","secret","token","password",
             "access_key","api_key","client_secret","credential","confidential"]

# 编译为大小写不敏感的正则
WORD_PATTERNS = [re.compile(re.escape(w), re.IGNORECASE) for w in WORDS]

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

def scan_comment_lines(ext: str, text: str) -> List[Tuple[int, str]]:
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
            for pat in WORD_PATTERNS:
                if pat.search(seg):
                    # 收敛一下行内容，避免 CSV 太长
                    excerpt = seg[:240]
                    hits.append((idx, excerpt))
                    break

    return hits

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
            for (lineno, excerpt) in hits:
                # 找到匹配的具体词（用于报告）
                matched = next((w for w in WORDS if re.search(re.escape(w), excerpt, re.IGNORECASE)), "")
                project_comment_rows.append([pid, full, ref, path, lineno, matched, excerpt])

        # 每处理完一个项目就写入CSV
        append_to_binary_csv(project_bin_rows)
        append_to_comment_csv(project_comment_rows)
        
        # 更新统计并显示当前项目结果
        total_binary_hits += len(project_bin_rows)
        total_comment_hits += len(project_comment_rows)
        
        if project_bin_rows or project_comment_rows:
            print(f"  -> 发现: 二进制文件 {len(project_bin_rows)} 个, 敏感注释 {len(project_comment_rows)} 条")
        else:
            print(f"  -> 无发现")
        
        # 对 API 客气一点
        time.sleep(0.1)

    print(f"\n扫描完成！")
    print(f"总计发现二进制文件：{total_binary_hits} 条")
    print(f"总计发现注释敏感词：{total_comment_hits} 条")
    print("结果文件：binary_hits.csv, comment_hits.csv")

if __name__ == "__main__":
    main()
# GitLab 代码审计工具

该工具用于扫描 GitLab 实例中的所有项目，自动检测潜在的安全风险，包括二进制文件和代码注释中的敏感信息。

## 功能特性

### 主要功能

1. **二进制文件扫描**：
   - 检测项目中提交的二进制文件（如 .zip, .doc, .pdf 等）
   - 识别可能包含敏感数据的压缩包和文档

2. **注释敏感词扫描**：
   - 扫描代码注释中的敏感词汇（密码、密钥、API Key 等）
   - 支持中英文敏感词检测
   - 支持多种编程语言的注释格式

3. **多语言支持**：
   - C/C++、Java、JavaScript、Python、Go、PHP 等主流语言
   - SQL、YAML、Shell 脚本等配置文件
   - Markdown、文本文档等

## 文件结构

- [`git_audit.py`](git_audit.py)：主脚本，执行 GitLab 项目扫描
- `binary_hits.csv`：输出的二进制文件检测结果
- `comment_hits.csv`：输出的注释敏感词检测结果

## 环境要求

- Python 3.6+
- requests 库：`pip install requests`

## 配置说明

### 必需配置

在脚本中直接修改以下变量：

```python
BASE = "http://10.26.31.128:80"  # GitLab 实例地址
TOKEN = "glpat-xxxxxxxxxxxxx"    # GitLab 访问令牌
```

### 可选配置

#### 敏感词自定义

通过环境变量 `SENSITIVE_WORDS` 自定义敏感词列表：

```bash
export SENSITIVE_WORDS="密码,secret,api_key,token"
```

默认敏感词包括：
- 中文：密码、密钥、私钥、机密、仅限内部、敏感
- 英文：secret、token、password、access_key、api_key、client_secret、credential、confidential

#### 其他配置项

- `MAX_BYTES`：单文件最大读取字节数（默认 1MB）
- `BINARY_EXTS`：需要检测的二进制文件扩展名
- `SKIP_DIRS`：跳过扫描的目录（如 .git、node_modules 等）

## 使用方法

### 1. 获取 GitLab Token

在 GitLab 个人设置页面生成访问令牌：
- 进入 User Settings → Access Tokens
- 创建新令牌，至少需要 `read_api` 和 `read_repository` 权限

### 2. 运行扫描

```bash
python git_audit.py
```

### 3. 查看结果

扫描完成后会生成两个 CSV 文件：

#### binary_hits.csv
包含检测到的二进制文件信息：
- `project_id`：项目 ID
- `project`：项目路径
- `branch`：分支名称
- `file_path`：文件路径

#### comment_hits.csv
包含检测到的敏感注释信息：
- `project_id`：项目 ID  
- `project`：项目路径
- `branch`：分支名称
- `file_path`：文件路径
- `line`：行号
- `keyword`：匹配的敏感词
- `comment_excerpt`：注释摘录（最多240字符）

## 支持的文件类型

### 代码文件
- **C系列**：.c, .h, .cpp, .hpp, .java, .js, .go 等
- **脚本语言**：.py, .rb, .sh, .ps1, .php 等  
- **配置文件**：.yml, .yaml, .toml, .ini, .properties 等
- **数据库**：.sql
- **文档**：.md, .txt, .rst

### 二进制文件
- **压缩包**：.zip, .tar, .gz, .rar, .7z
- **文档**：.doc, .docx, .pdf, .xls, .xlsx, .ppt, .pptx

## 注意事项

1. **权限要求**：确保提供的 Token 具有足够的项目访问权限
2. **网络限制**：脚本会自动处理 API 限流，包含重试机制
3. **性能考虑**：
   - 单文件最大读取 1MB，避免内存溢出
   - 自动跳过常见的依赖目录（node_modules、.git 等）
   - API 调用间有适当延时
4. **编码处理**：使用 UTF-8 解码，忽略无法解码的字符

## 输出示例

### 二进制文件检测
```csv
project_id,project,branch,file_path
123,example/project,main,docs/manual.pdf
124,another/repo,master,backup.zip
```

### 敏感注释检测
```csv
project_id,project,branch,file_path,line,keyword,comment_excerpt
123,example/project,main,src/config.py,15,password,# 默认密码是 admin123
124,another/repo,master,api/auth.js,42,api_key,// TODO: 替换这个临时的 API key
```

## 故障排除

### 常见问题

1. **Token 权限不足**
   ```
   解决方案：确保 Token 具有 read_api 和 read_repository 权限
   ```

2. **网络连接问题**
   ```
   解决方案：检查 GitLab 地址是否正确，网络是否可达
   ```

3. **Python 依赖缺失**
   ```bash
   pip install requests
   ```
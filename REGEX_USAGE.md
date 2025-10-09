# 正则表达式敏感词功能使用说明

## 概述

`git_audit.py` 现在支持混合使用普通字符串和正则表达式作为敏感词，通过环境变量 `SENSITIVE_WORDS` 进行配置。

## 配置格式

### 基本语法
- 普通字符串：直接写词汇，如 `password`、`密码`
- 正则表达式：使用 `regex:` 前缀，如 `regex:(?:api[_-]?key|access[_-]?token)`
- 多个敏感词用英文逗号 `,` 分隔

### 示例配置

#### 1. 混合使用（推荐）
```bash
export SENSITIVE_WORDS="密码,secret,regex:(?:api[_-]?key|access[_-]?token),regex:(?:mysql|postgres)://[^\\s]+"
```

#### 2. 只使用普通字符串
```bash
export SENSITIVE_WORDS="password,token,credential,密码,密钥"
```

#### 3. 只使用正则表达式
```bash
export SENSITIVE_WORDS="regex:\\b(?:pass|pwd)\\w*\\s*[=:]\\s*['\"][^'\"]+['\"],regex:(?:secret|private)[_-]?key"
```

## 正则表达式示例

### 常用模式

1. **API密钥类**
   ```
   regex:(?:api[_-]?key|access[_-]?token|secret[_-]?key)
   ```
   匹配：`api_key`, `api-key`, `access_token`, `secret_key` 等

2. **数据库连接串**
   ```
   regex:(?:mysql|postgres|mongodb)://[^\\s]+
   ```
   匹配：`mysql://user:pass@host/db`, `postgres://...` 等

3. **密码赋值**
   ```
   regex:\\b(?:pass|pwd|password)\\w*\\s*[=:]\\s*['\"][^'\"]+['\"]
   ```
   匹配：`password = "123456"`, `pwd: 'secret'` 等

4. **JWT Token**
   ```
   regex:eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*
   ```
   匹配标准JWT格式的token

5. **AWS访问密钥**
   ```
   regex:AKIA[0-9A-Z]{16}
   ```
   匹配AWS访问密钥ID格式

6. **私钥文件**
   ```
   regex:-----BEGIN [A-Z\\s]+ PRIVATE KEY-----
   ```
   匹配PEM格式私钥开头

## 注意事项

### 1. 转义字符
在正则表达式中使用反斜杠时需要双重转义：
- 错误：`regex:\b\w+`
- 正确：`regex:\\b\\w+`

### 2. 复杂模式建议
对于复杂的正则表达式，建议：
- 先在正则表达式测试工具中验证
- 使用简单的子模式组合
- 避免过于贪婪的匹配

### 3. 性能考虑
- 正则表达式比普通字符串匹配稍慢
- 避免过于复杂的正则表达式
- 合理使用量词，避免回溯

## 测试验证

使用提供的测试脚本验证配置：
```bash
python test_regex_words.py
```

## 实际使用

### Windows PowerShell
```powershell
$env:SENSITIVE_WORDS="密码,secret,regex:(?:api[_-]?key|access[_-]?token)"
python git_audit.py
```

### Linux/Mac
```bash
export SENSITIVE_WORDS="密码,secret,regex:(?:api[_-]?key|access[_-]?token)"
python git_audit.py
```

## 输出变化

在CSV输出文件中，`keyword` 列现在会显示：
- 普通字符串：原始词汇，如 `password`
- 正则表达式：会显示 `regex:...` 格式，便于识别匹配规则

这样可以帮助分析人员了解具体是哪个规则匹配了敏感内容。
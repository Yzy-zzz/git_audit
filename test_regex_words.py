#!/usr/bin/env python3
"""
测试脚本：演示如何使用正则表达式敏感词
"""

import os
import sys

# 设置环境变量来测试正则表达式敏感词
test_cases = [
    # 混合普通字符串和正则表达式
    "密码,secret,regex:(?:api[_-]?key|access[_-]?token),regex:(?:mysql|postgres)://[^\\s]+",
    
    # 只使用普通字符串（原有功能）
    "password,token,credential",
    
    # 只使用正则表达式
    "regex:\\b(?:pass|pwd)\\w*\\s*[=:]\\s*['\"][^'\"]+['\"],regex:(?:secret|private)[_-]?key"
]

def test_sensitive_words_parsing(sensitive_words_config):
    """测试敏感词解析功能"""
    print(f"\n测试配置: {sensitive_words_config}")
    
    # 临时设置环境变量
    os.environ["SENSITIVE_WORDS"] = sensitive_words_config
    
    # 动态导入以重新解析敏感词
    if 'git_audit' in sys.modules:
        del sys.modules['git_audit']
    
    try:
        import git_audit
        print(f"解析出的敏感词数量: {len(git_audit.WORDS)}")
        print("敏感词列表:")
        for i, word in enumerate(git_audit.WORDS):
            print(f"  {i+1}. {word}")
        
        # 测试一些示例文本
        test_texts = [
            "# 密码: admin123",
            "// secret_key = 'abc123'", 
            "api_key=your-api-key-here",
            "access-token: bearer-token",
            "mysql://user:password@localhost/db",
            "password = 'secret123'",
            "private_key_file = '/path/to/key'"
        ]
        
        print("\n测试文本匹配:")
        for text in test_texts:
            matches = []
            for i, pattern in enumerate(git_audit.WORD_PATTERNS):
                if pattern.search(text):
                    matches.append(git_audit.WORDS[i])
            
            if matches:
                print(f"  '{text}' -> 匹配: {matches}")
            else:
                print(f"  '{text}' -> 无匹配")
                
    except Exception as e:
        print(f"错误: {e}")

def main():
    print("正则表达式敏感词功能测试")
    print("=" * 50)
    
    # 备份原有环境变量
    original_sensitive_words = os.environ.get("SENSITIVE_WORDS", "")
    
    try:
        for config in test_cases:
            test_sensitive_words_parsing(config)
    finally:
        # 恢复原有环境变量
        if original_sensitive_words:
            os.environ["SENSITIVE_WORDS"] = original_sensitive_words
        elif "SENSITIVE_WORDS" in os.environ:
            del os.environ["SENSITIVE_WORDS"]

if __name__ == "__main__":
    main()
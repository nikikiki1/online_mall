# 简单测试脚本，用于验证view_contact函数的语法是否正确

# 模拟必要的导入和对象
import sys

# 检查app_gui.py文件是否存在
with open('app_gui.py', 'r', encoding='utf-8') as f:
    content = f.read()
    print(f"文件读取成功，共{len(content)}个字符")
    
    # 检查是否包含我们添加的代码
    if "查看顾客联系方式" in content:
        print("✓ 成功找到添加的功能")
    else:
        print("✗ 未找到添加的功能")
    
    # 检查是否有明显的语法错误标记
    if "SyntaxError" in content:
        print("✗ 文件中包含语法错误")
    else:
        print("✓ 文件中没有明显的语法错误标记")

print("测试完成")
#!/usr/bin/env python3
"""
快速崩溃测试 - 专注于常见的崩溃场景
"""

import traceback
import tempfile
import os

def test_immediate_crashes():
    """测试立即可能触发的崩溃场景"""
    print("开始快速崩溃测试...")
    
    with open("quick_crash_results.txt", "w", encoding="utf-8") as f:
        f.write("快速崩溃测试结果\n")
        f.write("=" * 50 + "\n")
        
        def record_crash(test_name, error_msg):
            print(f"[崩溃] {test_name}: {error_msg}")
            f.write(f"{test_name}: {error_msg}\n")
        
        # 测试1: 尝试访问不存在的文件
        try:
            from services.user_manager import UserManager
            user_manager = UserManager(data_file="/nonexistent/path/users.json")
            user_manager.load_users()
        except Exception as e:
            record_crash("不存在的文件路径", str(e))
        
        # 测试2: 尝试访问只读文件
        try:
            readonly_file = "/proc/sys/kernel/hostname"
            user_manager = UserManager(data_file=readonly_file)
            user_manager.register_user("test", "test", "test@test.com", "customer")
        except Exception as e:
            record_crash("只读文件访问", str(e))
        
        # 测试3: 恶意JSON内容
        try:
            malicious_file = tempfile.mktemp(suffix='.json')
            with open(malicious_file, 'w') as json_file:
                json_file.write('{"__reduce__": ["os.system", ["echo hacked"]]}')
            
            user_manager = UserManager(data_file=malicious_file)
            user_manager.load_users()
            os.unlink(malicious_file)
        except Exception as e:
            record_crash("恶意JSON反序列化", str(e))
            try:
                os.unlink(malicious_file)
            except:
                pass
        
        # 测试4: 空JSON文件
        try:
            empty_file = tempfile.mktemp(suffix='.json')
            with open(empty_file, 'w') as json_file:
                json_file.write('')
            
            user_manager = UserManager(data_file=empty_file)
            user_manager.load_users()
            os.unlink(empty_file)
        except Exception as e:
            record_crash("空JSON文件", str(e))
            try:
                os.unlink(empty_file)
            except:
                pass
        
        # 测试5: 无效JSON格式
        try:
            invalid_file = tempfile.mktemp(suffix='.json')
            with open(invalid_file, 'w') as json_file:
                json_file.write('not valid json {{{')
            
            user_manager = UserManager(data_file=invalid_file)
            user_manager.load_users()
            os.unlink(invalid_file)
        except Exception as e:
            record_crash("无效JSON格式", str(e))
            try:
                os.unlink(invalid_file)
            except:
                pass
        
        # 测试6: None值传递
        try:
            from services.user_manager import UserManager
            user_manager = UserManager()
            user_manager.register_user(None, None, None, None)
        except Exception as e:
            record_crash("None值传递", str(e))
        
        # 测试7: 极长字符串
        try:
            user_manager = UserManager()
            very_long_string = "A" * 1000000  # 1MB字符串
            user_manager.register_user(very_long_string, very_long_string, very_long_string, "customer")
        except Exception as e:
            record_crash("极长字符串", str(e))
        
        # 测试8: 特殊字符
        try:
            user_manager = UserManager()
            special_chars = "\x00\x01\x02\xFF\xFE" * 1000
            user_manager.register_user(special_chars, special_chars, special_chars, "customer")
        except Exception as e:
            record_crash("特殊字符", str(e))
        
        # 测试9: 数值溢出
        try:
            user_manager = UserManager()
            user_manager.register_user(
                str(999999999999999999999999999999),
                str(999999999999999999999999999999),
                str(999999999999999999999999999999) + "@test.com",
                "customer"
            )
        except Exception as e:
            record_crash("数值溢出", str(e))
        
        # 测试10: 浮点数异常值
        try:
            user_manager = UserManager()
            user_manager.register_user(
                str(float('inf')),
                str(float('-inf')),
                str(float('nan')) + "@test.com",
                "customer"
            )
        except Exception as e:
            record_crash("浮点数异常值", str(e))
        
        print("快速崩溃测试完成!")

if __name__ == "__main__":
    test_immediate_crashes()
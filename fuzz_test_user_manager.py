#!/usr/bin/env python3
"""
UserManager 模糊测试 - 测试用户注册和登录功能
"""

import os
import sys
import tempfile
import atheris

with atheris.instrument_imports():
    from services.user_manager import UserManager

def TestOneInput(data):
    """UserManager 模糊测试入口函数"""
    fdp = atheris.FuzzedDataProvider(data)
    
    # 创建临时文件用于测试
    tmp_file = tempfile.mktemp(suffix='_fuzz_users.json')
    try:
        with open(tmp_file, 'w') as f:
            f.write('[]')
        
        test_manager = UserManager(data_file=tmp_file)
        
        # 测试用户注册功能
        try:
            # 生成各种模糊输入
            username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            email = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50)) + "@test.com"
            role = fdp.PickValueInList(["customer", "merchant", "", "admin", "unknown"])
            
            if role == "merchant":
                shop_name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
                contact_info = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
                test_manager.register_user(username, password, email, role, 
                                         shop_name=shop_name, contact_info=contact_info)
            else:
                shipping_address = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
                phone_number = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 20))
                test_manager.register_user(username, password, email, role,
                                         shipping_address=shipping_address, phone_number=phone_number)
        except Exception:
            pass  # 忽略预期的异常
        
        # 测试用户登录功能
        try:
            login_username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            login_password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            test_manager.login_user(login_username, login_password)
        except Exception:
            pass
        
        # 测试用户查找功能
        try:
            search_username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            test_manager.get_user_by_username(search_username)
            
            # 测试用户ID查找
            user_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            test_manager.get_user_by_id(user_id)
        except Exception:
            pass
            
    finally:
        try:
            os.unlink(tmp_file)
        except:
            pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
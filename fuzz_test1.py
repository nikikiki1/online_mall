#!/usr/bin/env python3
"""
正确的 Atheris 模糊测试示例：针对用户注册功能
"""

import os
import sys
import tempfile
import atheris

# 1. 在 instrument_imports 上下文内导入，使Atheris能跟踪这些库的覆盖率
with atheris.instrument_imports():
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from services.user_manager import UserManager

def TestOneInput(data):
    """
    Atheris 标准入口函数。
    每次调用都是全新的、独立的。
    """
    fdp = atheris.FuzzedDataProvider(data)  # 使用官方数据提供器

    # 2. 为**本次**测试创建独立临时环境（关键！）
    tmp_file = tempfile.mktemp(suffix='_fuzz_users.json')
    # 写入初始空数据
    with open(tmp_file, 'w') as f:
        f.write('[]')

    try:
        # 创建独立的管理器实例
        test_manager = UserManager(data_file=tmp_file)

        # 3. 使用模糊数据生成输入参数
        username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        # 生成可能有效也可能无效的邮箱
        email_local = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 30))
        email = f"{email_local}@test.com"
        role = fdp.PickValueInList(["customer", "merchant"])

        # 4. 调用被测试函数
        # 所有未预期的异常（如 AttributeError、TypeError、KeyError等）都将被Atheris捕获并记录为崩溃
        test_manager.register_user(username, password, email, role)

        # 可以继续用同一个管理器测试登录等（状态是隔离的）
        # test_manager.login_user(username, password)

    finally:
        # 5. 清理本次测试的临时文件
        try:
            os.unlink(tmp_file)
        except:
            pass

# 6. 正确的 Atheris 启动方式
if __name__ == "__main__":
    # 如果使用 `-max_total_time=60` 等参数，需要通过 sys.argv 传递
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
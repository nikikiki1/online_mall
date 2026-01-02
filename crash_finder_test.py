#!/usr/bin/env python3
"""
专门寻找崩溃用例的模糊测试
专注于边缘情况和可能导致崩溃的场景
"""

import os
import sys
import tempfile
import traceback
import atheris

with atheris.instrument_imports():
    from services.order_manager import OrderManager
    from services.user_manager import UserManager
    from services.product_manager import ProductManager

def crash_test_one_input(data):
    """专门寻找崩溃用例的测试函数"""
    fdp = atheris.FuzzedDataProvider(data)
    
    # 创建临时文件
    user_tmp_file = tempfile.mktemp(suffix='_crash_users.json')
    product_tmp_file = tempfile.mktemp(suffix='_crash_products.json')
    order_tmp_file = tempfile.mktemp(suffix='_crash_orders.json')
    
    try:
        # 初始化空文件
        for tmp_file in [user_tmp_file, product_tmp_file, order_tmp_file]:
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write('[]')
        
        # 创建管理器
        user_manager = UserManager(data_file=user_tmp_file)
        product_manager = ProductManager(data_file=product_tmp_file)
        order_manager = OrderManager(product_manager, user_manager, data_file=order_tmp_file)
        
        # === 崩溃测试用例 1: 空值和None测试 ===
        test_cases_1 = [
            ("", "", "", "customer"),
            (None, None, None, None),
            (0, 0, 0, 0),
            (False, False, False, False),
        ]
        
        for username, password, email, user_type in test_cases_1:
            try:
                user_manager.register_user(username, password, email, user_type)
            except Exception as e:
                print(f"[CRASH] 注册用户失败: {e}")
                traceback.print_exc()
        
        # === 崩溃测试用例 2: 极端数值测试 ===
        extreme_values = [
            -999999999999999999999999999999,  # 极小整数
            999999999999999999999999999999,   # 极大整数
            float('inf'),                      # 正无穷
            float('-inf'),                     # 负无穷
            float('nan'),                      # NaN
            1e308,                            # 接近float最大值
            1e-308,                           # 接近float最小值
        ]
        
        for extreme_val in extreme_values:
            try:
                user_manager.register_user(
                    str(extreme_val), 
                    str(extreme_val), 
                    str(extreme_val), 
                    "customer"
                )
            except Exception as e:
                print(f"[CRASH] 极端值注册失败: {e}")
                traceback.print_exc()
        
        # === 崩溃测试用例 3: 超长字符串测试 ===
        long_strings = [
            "A" * 100000,    # 10万字符
            "B" * 1000000,   # 100万字符
            "\x00" * 1000,   # 1000个null字符
            "\xFF" * 1000,   # 1000个无效UTF-8字符
            "测试" * 100000, # 10万中文字符
        ]
        
        for long_str in long_strings:
            try:
                user_manager.register_user(long_str, long_str, f"{long_str}@test.com", "customer")
            except Exception as e:
                print(f"[CRASH] 超长字符串注册失败: {e}")
                traceback.print_exc()
        
        # === 崩溃测试用例 4: 商品创建崩溃测试 ===
        merchant_result, merchant_msg = user_manager.register_user(
            "crash_test_merchant", "password", "merchant@test.com", "merchant"
        )
        
        if merchant_result:
            # 商品创建的极端测试
            product_extreme_tests = [
                ("", "", -999999999, -999999999),  # 空名称和负值
                (None, None, float('inf'), float('inf')),  # None值和无穷大
                ("A" * 100000, "B" * 1000000, 999999999999999, 999999999999999),  # 超长描述和极大数值
            ]
            
            for name, desc, price, stock in product_extreme_tests:
                try:
                    product_manager.create_product(name, desc, price, stock, merchant_result.merchant_id)
                except Exception as e:
                    print(f"[CRASH] 商品创建失败: {e}")
                    traceback.print_exc()
        
        # === 崩溃测试用例 5: 订单创建崩溃测试 ===
        customer_result, customer_msg = user_manager.register_user(
            "crash_test_customer", "password", "customer@test.com", "customer"
        )
        
        if merchant_result and customer_result:
            product_result, product_msg = product_manager.create_product(
                "test_product", "test_description", 10.0, 100, merchant_result.merchant_id
            )
            
            if product_result:
                # 订单创建的崩溃测试
                order_crash_tests = [
                    (customer_result.user_id, product_result.product_id, -999999999999999),  # 负数量
                    (customer_result.user_id, product_result.product_id, float('inf')),     # 无穷大数量
                    ("invalid_user_id", product_result.product_id, 1),                      # 无效用户ID
                    (customer_result.user_id, "invalid_product_id", 1),                     # 无效商品ID
                    (None, None, None),                                                     # 全部None
                    ("", "", 0),                                                            # 空字符串和零
                ]
                
                for user_id, prod_id, quantity in order_crash_tests:
                    try:
                        order_manager.create_order(user_id, prod_id, quantity)
                    except Exception as e:
                        print(f"[CRASH] 订单创建失败: {e}")
                        traceback.print_exc()
        
        # === 崩溃测试用例 6: 文件系统攻击测试 ===
        attack_paths = [
            "../../../etc/passwd",          # 路径遍历攻击
            "/proc/self/environ",           # /proc文件系统攻击
            "\\\x00",                        # null字节攻击
            "A" * 10000 + ".json",          # 超长文件名
            "con.txt",                      # Windows保留名
            "nul.json",                     # Windows设备名
        ]
        
        for attack_path in attack_paths:
            try:
                attack_user_manager = UserManager(data_file=attack_path)
                attack_user_manager.register_user("test", "test", "test@test.com", "customer")
            except Exception as e:
                print(f"[CRASH] 文件系统攻击测试失败: {e}")
                traceback.print_exc()
        
        # === 崩溃测试用例 7: JSON序列化攻击 ===
        json_attacks = [
            '{"__reduce__": ["os.system", ["echo crash"]]}',  # pickle反序列化攻击
            '{"a": "A" * 100000000}',                        # 巨大JSON对象
            '[' + '{"a": "A"}' * 100000 + ']',               # 巨大JSON数组
        ]
        
        # 尝试写入恶意JSON到文件
        for i, json_attack in enumerate(json_attacks):
            try:
                attack_file = tempfile.mktemp(suffix=f'_attack_{i}.json')
                with open(attack_file, 'w', encoding='utf-8') as f:
                    f.write(json_attack)
                
                # 尝试读取恶意JSON
                attack_user_manager = UserManager(data_file=attack_file)
                # 这会触发load_users，可能导致崩溃
            except Exception as e:
                print(f"[CRASH] JSON攻击测试失败: {e}")
                traceback.print_exc()
        
        print(f"[INFO] 完成一轮崩溃测试，当前输入长度: {len(data)}")
        
    except Exception as e:
        print(f"[CRITICAL CRASH] 顶层异常: {e}")
        traceback.print_exc()
        
    finally:
        # 清理临时文件
        for tmp_file in [user_tmp_file, product_tmp_file, order_tmp_file]:
            try:
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)
            except:
                pass

if __name__ == "__main__":
    print("开始专门寻找崩溃用例的模糊测试...")
    atheris.Setup(sys.argv, crash_test_one_input)
    atheris.Fuzz()
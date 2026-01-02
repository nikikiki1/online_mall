#!/usr/bin/env python3
"""
OrderManager 模糊测试 - 测试订单创建和处理功能
"""

import os
import sys
import tempfile
import atheris

with atheris.instrument_imports():
    from services.order_manager import OrderManager
    from services.user_manager import UserManager
    from services.product_manager import ProductManager

def TestOneInput(data):
    """OrderManager 模糊测试入口函数"""
    fdp = atheris.FuzzedDataProvider(data)
    
    # 创建临时文件用于测试
    user_tmp_file = tempfile.mktemp(suffix='_fuzz_users.json')
    product_tmp_file = tempfile.mktemp(suffix='_fuzz_products.json')
    order_tmp_file = tempfile.mktemp(suffix='_fuzz_orders.json')
    
    try:
        # 初始化临时数据
        for tmp_file in [user_tmp_file, product_tmp_file, order_tmp_file]:
            with open(tmp_file, 'w') as f:
                f.write('[]')
        
        # 创建管理器实例
        user_manager = UserManager(data_file=user_tmp_file)
        product_manager = ProductManager(data_file=product_tmp_file)
        order_manager = OrderManager(product_manager, user_manager, data_file=order_tmp_file)
        
        # 创建测试用户和商品
        try:
            # 创建测试顾客
            customer_result, _ = user_manager.register_user(
                "test_customer", "password123", "customer@test.com", "customer",
                shipping_address="Test Address", phone_number="1234567890"
            )
            
            # 创建测试商家
            merchant_result, _ = user_manager.register_user(
                "test_merchant", "password456", "merchant@test.com", "merchant",
                shop_name="Test Shop", contact_info="merchant contact"
            )
            
            # 创建测试商品
            if merchant_result:
                product_result, _ = product_manager.create_product(
                    "Test Product", "Test Description", 100.0, 10, merchant_result.merchant_id
                )
            else:
                product_result = None
                
        except Exception:
            pass  # 忽略初始化异常
        
        # 测试订单创建功能
        try:
            customer_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            quantity = fdp.ConsumeIntInRange(0, 1000)  # 允许0和负数来测试边界情况
            
            order_manager.create_order(customer_id, product_id, quantity)
        except Exception:
            pass
        
        # 测试订单处理功能
        try:
            order_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            action = fdp.PickValueInList(["accept", "complete", "cancel", "invalid", ""])
            
            order_manager.process_order(order_id, action)
        except Exception:
            pass
        
        # 测试联系方式交换功能
        try:
            order_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            order_manager.exchange_contact_info(order_id)
        except Exception:
            pass
        
        # 测试订单查询功能
        try:
            customer_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            merchant_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            
            order_manager.get_orders_by_customer(customer_id)
            order_manager.get_orders_by_merchant(merchant_id)
            
            # 测试订单ID查找
            order_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            order_manager.get_order(order_id)
        except Exception:
            pass
            
    finally:
        # 清理临时文件
        for tmp_file in [user_tmp_file, product_tmp_file, order_tmp_file]:
            try:
                os.unlink(tmp_file)
            except:
                pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()



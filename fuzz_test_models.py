#!/usr/bin/env python3
"""
数据模型模糊测试 - 测试User、Order、Product等核心数据模型
"""

import os
import sys
import tempfile
import atheris

with atheris.instrument_imports():
    from models.user import User, Merchant, Customer
    from models.product import Product
    from models.order import Order

def TestUserModel(data):
    """用户模型模糊测试"""
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        # 测试基本User类
        username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        email = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        role = fdp.PickValueInList(["customer", "merchant", "admin", "", "invalid"])
        
        user = User(username, password, email, role)
        
        # 测试用户方法
        user.register()
        user.login(username, password)
        user.logout()
        
        # 测试空输入情况
        user.login("", "")
        
    except Exception:
        pass

def TestMerchantModel(data):
    """商家模型模糊测试"""
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        email = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        shop_name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        contact_info = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 200))
        
        merchant = Merchant(username, password, email, shop_name, contact_info)
        
        # 测试商家特定方法
        merchant.register()
        merchant.login(username, password)
        merchant.logout()
        
        # 测试空参数情况
        merchant.register()
        merchant.login("", "")
        
    except Exception:
        pass

def TestCustomerModel(data):
    """顾客模型模糊测试"""
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        username = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        password = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        email = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        shipping_address = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 200))
        phone_number = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 20))
        
        customer = Customer(username, password, email, shipping_address, phone_number)
        
        # 测试顾客特定方法
        customer.register()
        customer.login(username, password)
        customer.logout()
        
        # 测试空参数情况
        customer.register()
        customer.login("", "")
        
    except Exception:
        pass

def TestProductModel(data):
    """商品模型模糊测试"""
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
        description = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 200))
        price = fdp.ConsumeFloat()  # 允许负数和特殊值
        stock_quantity = fdp.ConsumeIntInRange(-1000, 1000)  # 允许负数
        merchant_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        
        product = Product(name, description, price, stock_quantity, merchant_id)
        
        # 测试商品方法
        product.update_info(name="new name")
        product.update_info(description="new description")
        product.update_info(price=99.99)
        
        # 测试库存操作
        quantity = fdp.ConsumeIntInRange(-100, 100)
        product.decrease_stock(quantity)
        product.increase_stock(quantity)
        
        # 测试状态操作
        product.activate()
        product.deactivate()
        product.auto_deactivate()
        
    except Exception:
        pass

def TestOrderModel(data):
    """订单模型模糊测试"""
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        customer_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
        quantity = fdp.ConsumeIntInRange(0, 1000)
        
        # 测试无ProductManager的情况
        order = Order(customer_id, product_id, quantity, None)
        
        # 测试订单方法
        order.calculate_total()
        
        # 测试状态更新
        new_status = fdp.PickValueInList(["pending", "accepted", "completed", "cancelled", "invalid", ""])
        order.update_status(new_status)
        
        # 测试特定状态方法
        order.accept()
        order.complete()
        order.cancel()
        
        # 测试字符串表示
        str(order)
        
    except Exception:
        pass

def TestOneInput(data):
    """数据模型模糊测试入口函数"""
    fdp = atheris.FuzzedDataProvider(data)
    
    # 随机选择要测试的模型
    test_choice = fdp.ConsumeIntInRange(1, 6)
    
    if test_choice == 1:
        TestUserModel(data)
    elif test_choice == 2:
        TestMerchantModel(data)
    elif test_choice == 3:
        TestCustomerModel(data)
    elif test_choice == 4:
        TestProductModel(data)
    elif test_choice == 5:
        TestOrderModel(data)
    else:
        # 综合测试
        TestUserModel(data)
        TestMerchantModel(data)
        TestCustomerModel(data)
        TestProductModel(data)
        TestOrderModel(data)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
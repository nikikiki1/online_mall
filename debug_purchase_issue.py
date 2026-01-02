#!/usr/bin/env python3
"""
购买问题诊断脚本
帮助分析为什么商品会显示已下架
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.product_manager import ProductManager
from services.user_manager import UserManager
from services.order_manager import OrderManager


def diagnose_purchase_issues():
    """诊断购买问题"""
    print("=== 商品购买问题诊断 ===\n")
    
    # 初始化管理器
    product_manager = ProductManager()
    user_manager = UserManager()
    
    # 检查所有商品
    all_products = list(product_manager.products.values())
    active_products = product_manager.get_all_products()
    
    print(f"📊 商品统计:")
    print(f"   总商品数: {len(all_products)}")
    print(f"   上架商品数: {len(active_products)}")
    print(f"   下架商品数: {len(all_products) - len(active_products)}")
    
    if not all_products:
        print("\n❌ 系统中没有商品，请先创建商品")
        return
    
    print("\n🔍 详细商品分析:")
    for i, product in enumerate(all_products, 1):
        status = "✅ 上架" if product.is_active else "❌ 下架"
        auto_deactivate = "⚠️  库存为0，应该下架" if product.stock_quantity <= 0 else ""
        
        print(f"\n商品 {i}: {product.name}")
        print(f"   ID: {product.product_id}")
        print(f"   价格: ¥{product.price}")
        print(f"   库存: {product.stock_quantity}")
        print(f"   状态: {status}")
        print(f"   商家ID: {product.merchant_id}")
        print(f"   上架日期: {product._listing_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if auto_deactivate:
            print(f"   {auto_deactivate}")
    
    # 模拟购买测试
    print("\n🛒 购买流程测试:")
    test_user = None
    
    # 创建一个测试用户
    test_username = f"debug_user_{len(user_manager.users)}"
    test_user, msg = user_manager.register_user(
        test_username, "password", f"{test_username}@test.com", "customer",
        shipping_address="测试地址", phone_number="13800138000"
    )
    
    if not test_user:
        print(f"   ❌ 无法创建测试用户: {msg}")
        return
    
    print(f"   ✅ 测试用户创建成功: {test_username}")
    
    # 测试购买每个商品
    for product in all_products:
        print(f"\n   测试购买: {product.name}")
        print(f"   商品ID: {product.product_id}")
        print(f"   当前库存: {product.stock_quantity}")
        print(f"   当前状态: {'上架' if product.is_active else '下架'}")
        
        # 尝试创建订单
        order_manager = OrderManager(product_manager, user_manager)
        order, order_msg = order_manager.create_order(
            test_user.user_id, product.product_id, 1
        )
        
        if order:
            print(f"   ✅ 购买成功! 订单ID: {order.order_id}")
            print(f"   📦 剩余库存: {product_manager.get_product(product.product_id).stock_quantity}")
        else:
            print(f"   ❌ 购买失败: {order_msg}")
            
            # 如果是商品已下架，提供详细信息
            if "已下架" in order_msg:
                product_obj = product_manager.get_product(product.product_id)
                print(f"   📋 下架原因分析:")
                print(f"      - 商品存在: {product_obj is not None}")
                print(f"      - 商品状态: {'上架' if product_obj and product_obj.is_active else '下架'}")
                print(f"      - 库存数量: {product_obj.stock_quantity if product_obj else 'N/A'}")
                
                if product_obj and product_obj.stock_quantity <= 0:
                    print(f"      - 下架原因: 库存耗尽（库存: {product_obj.stock_quantity}）")
                elif product_obj and not product_obj.is_active:
                    print(f"      - 下架原因: 手动下架或库存检查问题")


def test_manual_deactivation():
    """测试手动下架/上架功能"""
    print("\n=== 手动管理测试 ===")
    
    product_manager = ProductManager()
    if not product_manager.products:
        print("没有商品可以测试")
        return
    
    # 获取第一个商品
    product_id = list(product_manager.products.keys())[0]
    product = product_manager.get_product(product_id)
    
    print(f"测试商品: {product.name}")
    print(f"当前状态: {'上架' if product.is_active else '下架'}")
    
    # 测试手动下架
    print("\n🔽 测试手动下架...")
    result, msg = product_manager.toggle_product_status(product_id, activate=False)
    print(f"下架结果: {result}, 消息: {msg}")
    
    # 测试手动上架
    print("\n🔼 测试手动上架...")
    result, msg = product_manager.toggle_product_status(product_id, activate=True)
    print(f"上架结果: {result}, 消息: {msg}")


if __name__ == "__main__":
    diagnose_purchase_issues()
    test_manual_deactivation()
    
    print("\n=== 建议解决方案 ===")
    print("1. 如果商品因库存为0而下架：增加库存")
    print("2. 如果商品被手动下架：使用上架功能")
    print("3. 如果是界面显示问题：检查前端代码")
    print("4. 如果是用户ID问题：确保使用正确的用户ID")
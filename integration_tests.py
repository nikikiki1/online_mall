#!/usr/bin/env python3
"""
集成测试脚本
测试在线商城系统各模块间的交互和集成
"""

import sys
import os
import time
import json
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, List, Any, Tuple
import traceback

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.user_manager import UserManager
from services.product_manager import ProductManager
from services.order_manager import OrderManager
from models.user import User, Merchant, Customer
from models.product import Product
from models.order import Order

class IntegrationTestResults:
    """集成测试结果收集器"""
    def __init__(self):
        self.test_results = []
        self.passed_tests = 0
        self.failed_tests = 0
        self.start_time = time.time()
        
    def add_test_result(self, test_name: str, passed: bool, expected: str, actual: str, details: str = ""):
        """添加测试结果"""
        result = {
            'test_name': test_name,
            'passed': passed,
            'expected': expected,
            'actual': actual,
            'details': details,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.test_results.append(result)
        
        if passed:
            self.passed_tests += 1
        else:
            self.failed_tests += 1
            
    def get_summary(self) -> Dict[str, Any]:
        """获取测试摘要"""
        end_time = time.time()
        return {
            'total_tests': len(self.test_results),
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'success_rate': (self.passed_tests / len(self.test_results) * 100) if self.test_results else 0,
            'duration': round(end_time - self.start_time, 2)
        }

class IntegrationTestSuite:
    """集成测试套件"""
    
    def __init__(self):
        self.results = IntegrationTestResults()
        self.user_manager = None
        self.product_manager = None
        self.order_manager = None
        
    def setup_test_environment(self):
        """设置测试环境"""
        try:
            print("设置测试环境...")
            
            # 创建测试数据目录
            test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
            os.makedirs(test_data_dir, exist_ok=True)
            
            # 清空数据文件
            self.clear_data_files()
            
            # 初始化管理器
            self.user_manager = UserManager(os.path.join(test_data_dir, 'users.json'))
            self.product_manager = ProductManager(os.path.join(test_data_dir, 'products.json'))
            self.order_manager = OrderManager(
                self.product_manager, 
                self.user_manager, 
                os.path.join(test_data_dir, 'orders.json')
            )
            
            print("测试环境设置完成")
            return True
            
        except Exception as e:
            print(f"测试环境设置失败: {e}")
            traceback.print_exc()
            return False
    
    def clear_data_files(self):
        """清空数据文件"""
        test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        data_files = [
            os.path.join(test_data_dir, 'users.json'),
            os.path.join(test_data_dir, 'products.json'),
            os.path.join(test_data_dir, 'orders.json')
        ]
        
        for file_path in data_files:
            if os.path.exists(file_path):
                os.remove(file_path)
    
    def test_user_product_integration(self) -> bool:
        """
        第一组集成测试：用户管理与产品管理集成测试
        测试方法：自底向上集成
        """
        print("\n" + "="*60)
        print("第一组集成测试：用户管理与产品管理集成")
        print("测试方法：自底向上集成")
        print("="*60)
        
        try:
            # 测试用例 1: 商家创建产品
            merchant, msg = self.user_manager.register_user(
                username="integration_merchant",
                password="password123",
                email="integration@test.com",
                role="merchant",
                shop_name="集成测试商店",
                contact_info="integration@test.com"
            )
            
            if not merchant:
                self.results.add_test_result(
                    "商家创建产品集成测试",
                    False,
                    "商家注册成功",
                    f"商家注册失败: {msg}",
                    "用户注册失败，无法继续测试"
                )
                return False
            
            product, msg = self.product_manager.create_product(
                name="集成测试商品",
                description="用于集成测试的商品",
                price=299.99,
                stock_quantity=50,
                merchant_id=merchant.user_id
            )
            
            if not product:
                self.results.add_test_result(
                    "商家创建产品集成测试",
                    False,
                    "产品创建成功",
                    f"产品创建失败: {msg}",
                    "产品创建失败，无法继续测试"
                )
                return False
            
            # 验证集成：产品与商家的关联
            merchant_products = self.product_manager.get_products_by_merchant(merchant.user_id)
            expected_count = 1
            actual_count = len(merchant_products)
            
            passed = actual_count == expected_count and product in merchant_products
            self.results.add_test_result(
                "商家创建产品集成测试",
                passed,
                f"商家有{expected_count}个产品",
                f"商家有{actual_count}个产品",
                f"产品ID: {product.product_id}, 商家ID: {merchant.user_id}"
            )
            
            # 测试用例 2: 商家更新产品信息
            success, msg = self.product_manager.update_product(
                product.product_id,
                name="更新后的集成测试商品",
                price=199.99
            )
            
            updated_product = self.product_manager.get_product(product.product_id)
            merchant_updated_products = self.product_manager.get_products_by_merchant(merchant.user_id)
            expected_name = "更新后的集成测试商品"
            actual_name = updated_product.name
            
            passed = actual_name == expected_name and updated_product in merchant_updated_products
            self.results.add_test_result(
                "商家更新产品集成测试",
                passed,
                f"产品名称应为'{expected_name}'",
                f"实际产品名称为'{actual_name}'",
                f"更新前: {product.name}, 更新后: {updated_product.name}"
            )
            
            # 测试用例 3: 产品搜索与商家信息关联
            search_results = self.product_manager.search_products("集成测试")
            expected_count = 1
            actual_count = len(search_results)
            
            found_product = search_results[0] if search_results else None
            merchant_info = self.user_manager.get_user_by_id(found_product.merchant_id) if found_product else None
            
            passed = (actual_count == expected_count and 
                     found_product and 
                     merchant_info and 
                     merchant_info.shop_name == "集成测试商店")
            
            self.results.add_test_result(
                "产品搜索与商家信息关联测试",
                passed,
                "搜索结果包含正确的商家信息",
                f"找到{actual_count}个产品，商家信息{'正确' if merchant_info else '错误'}",
                f"搜索关键词: '集成测试', 商家: {merchant_info.shop_name if merchant_info else 'None'}"
            )
            
            print("第一组集成测试完成")
            return True
            
        except Exception as e:
            print(f"第一组集成测试失败: {e}")
            traceback.print_exc()
            return False
    
    def test_product_order_integration(self) -> bool:
        """
        第二组集成测试：产品管理与订单管理集成测试
        测试方法：自顶向下集成
        """
        print("\n" + "="*60)
        print("第二组集成测试：产品管理与订单管理集成")
        print("测试方法：自顶向下集成")
        print("="*60)
        
        try:
            # 设置测试数据
            merchant, msg = self.user_manager.register_user(
                username="order_merchant",
                password="password456",
                email="order@test.com",
                role="merchant",
                shop_name="订单测试商店",
                contact_info="order@test.com"
            )
            
            if not merchant:
                self.results.add_test_result(
                    "订单管理集成测试初始化",
                    False,
                    "商家注册成功",
                    f"商家注册失败: {msg}",
                    "用户注册失败，无法继续测试"
                )
                return False
            
            product, msg = self.product_manager.create_product(
                name="订单测试商品",
                description="用于订单测试的商品",
                price=99.99,
                stock_quantity=100,
                merchant_id=merchant.user_id
            )
            
            if not product:
                self.results.add_test_result(
                    "订单管理集成测试初始化",
                    False,
                    "产品创建成功",
                    f"产品创建失败: {msg}",
                    "产品创建失败，无法继续测试"
                )
                return False
            
            customer, msg = self.user_manager.register_user(
                username="order_customer",
                password="password789",
                email="customer@test.com",
                role="customer",
                shipping_address="订单测试地址",
                phone_number="13800138001"
            )
            
            if not customer:
                self.results.add_test_result(
                    "订单管理集成测试初始化",
                    False,
                    "顾客注册成功",
                    f"顾客注册失败: {msg}",
                    "用户注册失败，无法继续测试"
                )
                return False
            
            # 测试用例 1: 创建订单与库存管理集成
            initial_stock = product.stock_quantity
            order_quantity = 5
            
            order, msg = self.order_manager.create_order(
                customer_id=customer.user_id,
                product_id=product.product_id,
                quantity=order_quantity
            )
            
            if not order:
                self.results.add_test_result(
                    "订单创建与库存管理集成测试",
                    False,
                    "订单创建成功",
                    f"订单创建失败: {msg}",
                    "订单创建失败，无法继续测试"
                )
                return False
            
            # 验证库存减少
            updated_product = self.product_manager.get_product(product.product_id)
            expected_stock = initial_stock - order_quantity
            actual_stock = updated_product.stock_quantity
            
            passed = actual_stock == expected_stock and order.status == "pending"
            self.results.add_test_result(
                "订单创建与库存管理集成测试",
                passed,
                f"库存应为{expected_stock}，订单状态应为'pending'",
                f"实际库存{actual_stock}，订单状态'{order.status}'",
                f"初始库存: {initial_stock}, 订购数量: {order_quantity}"
            )
            
            # 测试用例 2: 订单处理与商品状态集成
            
            # 接受订单
            success, msg = self.order_manager.process_order(order.order_id, "accept")
            
            # 获取更新后的订单状态
            processed_order = self.order_manager.get_order(order.order_id)
            
            # 验证订单状态变化
            expected_status = "accepted"
            actual_status = processed_order.status
            
            passed = actual_status == expected_status
            
            self.results.add_test_result(
                "订单处理与状态管理集成测试",
                passed,
                f"订单状态应为'{expected_status}'",
                f"实际订单状态'{actual_status}'",
                f"订单ID: {order.order_id}, 处理动作: 'accept'"
            )
            
            # 测试用例 3: 完成订单与库存最终确认
            
            # 完成订单
            success, msg = self.order_manager.process_order(order.order_id, "complete")
            
            # 获取完成后的订单状态
            completed_order = self.order_manager.get_order(order.order_id)
            
            # 验证最终状态
            final_product = self.product_manager.get_product(product.product_id)
            expected_final_stock = initial_stock - order_quantity
            actual_final_stock = final_product.stock_quantity
            
            passed = (completed_order.status == "completed" and 
                     actual_final_stock == expected_final_stock)
            
            self.results.add_test_result(
                "订单完成与库存最终确认集成测试",
                passed,
                f"订单状态应为'completed'，最终库存应为{expected_final_stock}",
                f"订单状态'{completed_order.status}'，最终库存{actual_final_stock}",
                f"库存变化: {initial_stock} -> {actual_final_stock}"
            )
            
            # 测试用例 4: 订单查询与商品信息集成
            
            customer_orders = self.order_manager.get_orders_by_customer(customer.user_id)
            expected_order_count = 1
            actual_order_count = len(customer_orders)
            
            found_order = customer_orders[0] if customer_orders else None
            order_product = self.product_manager.get_product(found_order.product_id) if found_order else None
            
            passed = (actual_order_count == expected_order_count and
                     found_order and
                     order_product and
                     order_product.name == "订单测试商品")
            
            self.results.add_test_result(
                "订单查询与商品信息集成测试",
                passed,
                f"顾客应有{expected_order_count}个订单，商品信息正确",
                f"顾客有{actual_order_count}个订单，商品信息{'正确' if order_product else '错误'}",
                f"订单ID: {found_order.order_id if found_order else 'None'}"
            )
            
            print("第二组集成测试完成")
            return True
            
        except Exception as e:
            print(f"第二组集成测试失败: {e}")
            traceback.print_exc()
            return False
    
    def test_full_system_integration(self) -> bool:
        """
        第三组集成测试：全系统集成测试
        测试方法：混合集成（自顶向下+自底向上）
        """
        print("\n" + "="*60)
        print("第三组集成测试：全系统集成测试")
        print("测试方法：混合集成")
        print("="*60)
        
        # 创建测试数据目录
        test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        
        try:
            # 测试用例 1: 完整购物流程
            
            # 创建多个商家和商品
            merchants = []
            products = []
            
            for i in range(3):
                merchant, msg = self.user_manager.register_user(
                    username=f"full_merchant_{i}",
                    password="password123",
                    email=f"fullmerchant{i}@test.com",
                    role="merchant",
                    shop_name=f"完整测试商店{i+1}",
                    contact_info=f"fullmerchant{i}@test.com"
                )
                if merchant:
                    merchants.append(merchant)
                else:
                    print(f"警告: 商家 {i} 注册失败: {msg}")
                
                for j in range(2):
                    product, msg = self.product_manager.create_product(
                        name=f"完整测试商品{i}_{j}",
                        description=f"完整流程测试商品{j+1}",
                        price=50.0 + i * 10 + j * 5,
                        stock_quantity=20,
                        merchant_id=merchant.user_id
                    )
                    if product:
                        products.append(product)
                    else:
                        print(f"警告: 商品 {i}_{j} 创建失败: {msg}")
            
            # 创建多个顾客
            customers = []
            for i in range(3):
                customer, msg = self.user_manager.register_user(
                    username=f"full_customer_{i}",
                    password="password456",
                    email=f"fullcustomer{i}@test.com",
                    role="customer",
                    shipping_address=f"完整测试地址{i+1}",
                    phone_number=f"13800{i:08d}"
                )
                if customer:
                    customers.append(customer)
                else:
                    print(f"警告: 顾客 {i} 注册失败: {msg}")
            
            # 顾客进行购物
            orders = []
            for i, customer in enumerate(customers):
                # 每个顾客购买不同商家的商品
                for j, product in enumerate(products[:3]):  # 每个顾客买前3个商品
                    if j % 2 == i % 2:  # 错开购买模式
                        order, msg = self.order_manager.create_order(
                            customer_id=customer.user_id,
                            product_id=product.product_id,
                            quantity=1 + i  # 不同顾客买不同数量
                        )
                        if order:
                            orders.append(order)
                            # 处理订单
                            self.order_manager.process_order(order.order_id, "accept")
                            self.order_manager.process_order(order.order_id, "complete")
                        else:
                            print(f"警告: 订单创建失败: {msg}")
            
            # 验证集成结果
            expected_orders = 5  # 根据购买逻辑计算
            actual_orders = len(orders)
            
            # 验证库存变化
            total_stock_decrease = 0
            for i, product in enumerate(products[:3]):
                updated_product = self.product_manager.get_product(product.product_id)
                stock_decrease = 20 - updated_product.stock_quantity
                total_stock_decrease += stock_decrease
            
            # 计算预期库存减少量
            expected_stock_decrease = 0
            for i, customer in enumerate(customers):
                for j, product in enumerate(products[:3]):
                    if j % 2 == i % 2:  # 符合购买条件的订单
                        quantity = 1 + i  # 购买数量
                        expected_stock_decrease += quantity
            
            passed = actual_orders == expected_orders and total_stock_decrease == expected_stock_decrease
            
            self.results.add_test_result(
                "完整购物流程集成测试",
                passed,
                f"应创建{expected_orders}个订单，库存减少{expected_stock_decrease}",
                f"实际创建{actual_orders}个订单，库存减少{total_stock_decrease}",
                f"商家数量: {len(merchants)}, 商品数量: {len(products)}, 顾客数量: {len(customers)}"
            )
            
            # 测试用例 2: 数据持久化与系统重启集成
            
            # 保存当前状态
            system_state = {
                'merchants': len(merchants),
                'products': len(products),
                'customers': len(customers),
                'orders': len(orders),
                'timestamp': time.time()
            }
            
            # 模拟系统重启（重新初始化管理器）
            new_user_manager = UserManager(os.path.join(test_data_dir, 'users.json'))
            new_product_manager = ProductManager(os.path.join(test_data_dir, 'products.json'))
            new_order_manager = OrderManager(
                new_product_manager, 
                new_user_manager,
                os.path.join(test_data_dir, 'orders.json')
            )
            
            # 验证数据完整性
            loaded_merchants = [u for u in new_user_manager.users.values() if isinstance(u, Merchant)]
            loaded_products = list(new_product_manager.products.values())
            loaded_orders = list(new_order_manager.orders.values())
            
            expected_merchants = 3
            expected_products = 6
            expected_orders = 5
            
            actual_merchants = len(loaded_merchants)
            actual_products = len(loaded_products)
            actual_orders = len(loaded_orders)
            
            passed = (actual_merchants == expected_merchants and
                     actual_products == expected_products and
                     actual_orders == expected_orders)
            
            self.results.add_test_result(
                "数据持久化与系统重启集成测试",
                passed,
                f"加载数据: 商家{expected_merchants}个, 商品{expected_products}个, 订单{expected_orders}个",
                f"实际加载: 商家{actual_merchants}个, 商品{actual_products}个, 订单{actual_orders}个",
                f"系统状态保存时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(system_state['timestamp']))}"
            )
            
            # 测试用例 3: 跨模块数据一致性
            
            # 验证订单中的商品信息与当前商品信息一致
            inconsistent_data = False
            for order in loaded_orders:
                current_product = new_product_manager.get_product(order.product_id)
                if not current_product:
                    inconsistent_data = True
                    break
                
                # 检查商品是否属于正确的商家
                product_merchant = new_user_manager.get_user_by_id(current_product.merchant_id)
                if not product_merchant or not isinstance(product_merchant, Merchant):
                    inconsistent_data = True
                    break
            
            passed = not inconsistent_data
            
            self.results.add_test_result(
                "跨模块数据一致性集成测试",
                passed,
                "所有订单引用的商品和商家信息应保持一致",
                f"数据一致性状态: {'一致' if not inconsistent_data else '不一致'}",
                f"检查了{len(loaded_orders)}个订单的数据完整性"
            )
            
            print("第三组集成测试完成")
            return True
            
        except Exception as e:
            print(f"第三组集成测试失败: {e}")
            traceback.print_exc()
            return False
    
    def run_all_tests(self) -> bool:
        """运行所有集成测试"""
        print("开始集成测试套件")
        print("="*60)
        
        # 设置测试环境
        if not self.setup_test_environment():
            return False
        
        # 运行三组集成测试
        success1 = self.test_user_product_integration()
        success2 = self.test_product_order_integration()
        success3 = self.test_full_system_integration()
        
        # 生成测试报告
        self.generate_test_report()
        
        return success1 and success2 and success3
    
    def generate_test_report(self):
        """生成测试报告"""
        print("\n" + "="*80)
        print("集成测试报告")
        print("="*80)
        
        summary = self.results.get_summary()
        
        print(f"\n测试摘要:")
        print(f"- 总测试数: {summary['total_tests']}")
        print(f"- 通过测试: {summary['passed_tests']}")
        print(f"- 失败测试: {summary['failed_tests']}")
        print(f"- 成功率: {summary['success_rate']:.1f}%")
        
        print(f"\n详细测试结果:")
        print("-" * 80)
        
        for i, result in enumerate(self.results.test_results, 1):
            status = "PASS" if result['passed'] else "FAIL"
            print(f"\n{i}. {result['test_name']} - {status}")
            print(f"   预期: {result['expected']}")
            print(f"   实际: {result['actual']}")
        
        print("\n" + "="*80)

def main():
    """主函数"""
    test_suite = IntegrationTestSuite()
    
    try:
        success = test_suite.run_all_tests()
        
        if success:
            print("\n所有集成测试执行完成")
            return 0
        else:
            print("\n部分集成测试失败")
            return 1
            
    except Exception as e:
        print(f"\n集成测试执行异常: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
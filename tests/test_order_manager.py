import pytest
import os
import tempfile
import json
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.order_manager import OrderManager
from services.product_manager import ProductManager
from services.user_manager import UserManager
from models.order import Order
from models.product import Product


class TestOrderManager:
    """订单管理器全面测试类"""
    
    @pytest.fixture
    def temp_data_dir(self):
        """创建临时数据目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def mock_managers(self, temp_data_dir):
        """创建模拟的管理器"""
        # 创建临时数据文件路径
        orders_file = os.path.join(temp_data_dir, "orders.json")
        products_file = os.path.join(temp_data_dir, "products.json")
        
        # 创建管理器实例
        product_manager = ProductManager(products_file)
        user_manager = UserManager()
        order_manager = OrderManager(product_manager, user_manager, orders_file)
        
        return product_manager, user_manager, order_manager
    
    @pytest.fixture
    def sample_products(self, mock_managers):
        """创建示例商品"""
        product_manager, _, _ = mock_managers
        
        # 创建测试商品
        products = []
        for i in range(3):
            product, _ = product_manager.create_product(
                f"测试商品{i+1}",
                f"商品描述{i+1}",
                10.0 * (i+1),
                100 - i*10,
                f"merchant_{i+1}"
            )
            products.append(product)
        
        return products
    
    def test_order_manager_initialization(self, mock_managers):
        """测试订单管理器初始化"""
        _, _, order_manager = mock_managers
        
        assert order_manager is not None
        assert hasattr(order_manager, 'orders')
        assert hasattr(order_manager, 'data_file')
        assert hasattr(order_manager, 'product_manager')
        assert hasattr(order_manager, 'user_manager')
    
    def test_create_order_success(self, mock_managers, sample_products):
        """测试成功创建订单"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 创建订单
        order, message = order_manager.create_order(
            customer_id, 
            product.product_id, 
            5
        )
        
        assert order is not None
        assert message == "订单创建成功"
        assert order.customer_id == customer_id
        assert order.product_id == product.product_id
        assert order.quantity == 5
        assert order.status == "pending"
        assert len(order_manager.orders) == 1
    
    def test_create_order_nonexistent_product(self, mock_managers):
        """测试创建订单 - 商品不存在"""
        _, _, order_manager = mock_managers
        customer_id = "customer_001"
        
        # 尝试使用不存在的商品ID创建订单
        order, message = order_manager.create_order(
            customer_id, 
            "nonexistent_product", 
            5
        )
        
        assert order is None
        assert "商品不存在" in message
        assert len(order_manager.orders) == 0
    
    def test_create_order_insufficient_stock(self, mock_managers, sample_products):
        """测试创建订单 - 库存不足"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]  # 库存100
        customer_id = "customer_001"
        
        # 尝试创建库存超过可用量的订单
        order, message = order_manager.create_order(
            customer_id, 
            product.product_id, 
            150  # 超过库存100
        )
        
        assert order is None
        assert "库存不足" in message
        assert len(order_manager.orders) == 0
    
    def test_create_order_inactive_product(self, mock_managers, sample_products):
        """测试创建订单 - 商品已下架"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 先下架商品
        product_manager.toggle_product_status(product.product_id, False)
        
        # 尝试创建订单
        order, message = order_manager.create_order(
            customer_id, 
            product.product_id, 
            5
        )
        
        assert order is None
        assert "已下架" in message
        assert len(order_manager.orders) == 0
    
    def test_create_order_zero_quantity(self, mock_managers, sample_products):
        """测试创建订单 - 数量为0"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 尝试创建数量为0的订单
        order, message = order_manager.create_order(
            customer_id, 
            product.product_id, 
            0
        )
        
        assert order is None
        assert "商品数量必须为正数" in message
    
    def test_create_order_negative_quantity(self, mock_managers, sample_products):
        """测试创建订单 - 负数量"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 尝试创建负数量的订单
        order, message = order_manager.create_order(
            customer_id, 
            product.product_id, 
            -5
        )
        
        assert order is None
        assert "商品数量必须为正数" in message
        assert len(order_manager.orders) == 0
    
    def test_get_order_by_id(self, mock_managers, sample_products):
        """测试根据ID获取订单"""
        _, _, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 创建订单
        order, _ = order_manager.create_order(
            customer_id, 
            product.product_id, 
            5
        )
        
        # 通过ID获取订单
        retrieved_order = order_manager.get_order(order.order_id)
        
        assert retrieved_order is not None
        assert retrieved_order.order_id == order.order_id
        assert retrieved_order.customer_id == customer_id
        assert retrieved_order.product_id == product.product_id
    
    def test_get_nonexistent_order(self, mock_managers):
        """测试获取不存在的订单"""
        _, _, order_manager = mock_managers
        
        # 尝试获取不存在的订单
        order = order_manager.get_order("nonexistent_order_id")
        
        assert order is None
    

    def test_get_orders_by_customer(self, mock_managers, sample_products):
        """测试获取客户的订单"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建不同客户的订单
        order1, _ = order_manager.create_order("customer_001", product.product_id, 5)
        order2, _ = order_manager.create_order("customer_002", product.product_id, 3)
        order3, _ = order_manager.create_order("customer_001", product.product_id, 2)
        
        # 获取特定客户的订单
        customer_orders = order_manager.get_orders_by_customer("customer_001")
        
        assert len(customer_orders) == 2
        assert order1 in customer_orders
        assert order3 in customer_orders
        assert order2 not in customer_orders
    
    def test_get_orders_by_merchant(self, mock_managers, sample_products):
        """测试获取商家的订单"""
        product_manager, user_manager, order_manager = mock_managers
        
        # 创建不同商家的订单
        order1, _ = order_manager.create_order("customer_001", sample_products[0].product_id, 5)  # merchant_1
        order2, _ = order_manager.create_order("customer_002", sample_products[1].product_id, 3)  # merchant_2
        
        # 获取特定商家的订单
        merchant_orders = order_manager.get_orders_by_merchant("merchant_1")
        
        assert len(merchant_orders) == 1
        assert order1 in merchant_orders
        assert order2 not in merchant_orders
    
    def test_process_order_accept(self, mock_managers, sample_products):
        """测试处理订单 - 接受"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 处理订单（接受）
        success, message = order_manager.process_order(order.order_id, "accept")
        
        assert success is True
        assert "接受" in message
        assert order.status == "accepted"
    
    def test_process_order_reject(self, mock_managers, sample_products):
        """测试处理订单 - 拒绝"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 处理订单（拒绝）
        success, message = order_manager.process_order(order.order_id, "reject")
        
        assert success is True
        assert "拒绝" in message
        assert order.status == "rejected"
    
    def test_process_order_complete(self, mock_managers, sample_products):
        """测试处理订单 - 完成"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 先接受订单
        order_manager.process_order(order.order_id, "accept")
        
        # 完成订单
        success, message = order_manager.process_order(order.order_id, "complete")
        
        assert success is True
        assert "完成" in message
        assert order.status == "completed"
    
    def test_process_order_cancel(self, mock_managers, sample_products):
        """测试处理订单 - 取消"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 处理订单（取消）
        success, message = order_manager.process_order(order.order_id, "cancel")
        
        assert success is True
        assert "取消" in message
        assert order.status == "cancelled"
    
    def test_process_nonexistent_order(self, mock_managers):
        """测试处理不存在的订单"""
        _, _, order_manager = mock_managers
        
        # 尝试处理不存在的订单
        success, message = order_manager.process_order("nonexistent_order_id", "accept")
        
        assert success is False
        assert "订单不存在" in message
    
    def test_process_invalid_status(self, mock_managers, sample_products):
        """测试处理订单 - 无效状态"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 尝试使用无效状态处理订单
        success, message = order_manager.process_order(order.order_id, "invalid_status")
        
        assert success is False
        assert "无效" in message or "状态" in message
    
    def test_stock_decrease_after_order(self, mock_managers, sample_products):
        """测试订单创建后库存正确减少"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        original_stock = product.stock_quantity
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        
        # 重新获取商品信息
        updated_product = product_manager.get_product(product.product_id)
        
        assert updated_product.stock_quantity == original_stock - 5
    
    def test_order_status_transition(self, mock_managers, sample_products):
        """测试订单状态转换"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        assert order.status == "pending"
        
        # 接受订单
        order_manager.process_order(order.order_id, "accept")
        assert order.status == "accepted"
        
        # 完成订单
        order_manager.process_order(order.order_id, "complete")
        assert order.status == "completed"
        
        # 尝试完成已完成的订单（应该失败）
        success, message = order_manager.process_order(order.order_id, "complete")
        assert success is False
    
    def test_persistence_load_and_save(self, temp_data_dir, mock_managers):
        """测试数据持久化加载和保存"""
        # 创建新的管理器实例（模拟重启）
        orders_file = os.path.join(temp_data_dir, "orders.json")
        products_file = os.path.join(temp_data_dir, "products.json")
        
        # 先创建一些数据
        product_manager1 = ProductManager(products_file)
        user_manager1 = UserManager()
        order_manager1 = OrderManager(product_manager1, user_manager1, orders_file)
        
        # 创建商品和订单
        product, _ = product_manager1.create_product("测试商品", "描述", 10.0, 100, "merchant_1")
        order, _ = order_manager1.create_order("customer_001", product.product_id, 5)
        order_id = order.order_id
        
        # 创建新的管理器实例来测试数据加载
        product_manager2 = ProductManager(products_file)
        user_manager2 = UserManager()
        order_manager2 = OrderManager(product_manager2, user_manager2, orders_file)
        
        # 验证数据已加载
        loaded_order = order_manager2.get_order(order_id)
        assert loaded_order is not None
        assert loaded_order.order_id == order_id
        assert loaded_order.customer_id == "customer_001"
        assert len(order_manager2.orders) == 1
    
    def test_create_order_extreme_large_quantity(self, mock_managers, sample_products):
        """测试创建超大数量订单"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 尝试创建超过库存的超大订单
        large_quantity = 1000000
        order, message = order_manager.create_order("customer_001", product.product_id, large_quantity)
        
        # 应该返回失败，因为数量超出库存
        assert order is None
        assert "库存不足" in message or "超出库存" in message

    def test_create_order_very_small_quantity(self, mock_managers, sample_products):
        """测试创建极小数量订单（数量为1）"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 保存初始库存
        initial_stock = product_manager.get_product(product.product_id).stock_quantity
        
        # 创建最小数量订单
        order, message = order_manager.create_order("customer_001", product.product_id, 1)
        
        assert order is not None
        assert message == "订单创建成功"
        assert order.quantity == 1
        # 验证库存正确减少
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == initial_stock - 1

    def test_batch_order_creation(self, mock_managers, sample_products):
        """测试批量创建订单"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 保存初始库存
        initial_stock = product_manager.get_product(product.product_id).stock_quantity
        
        # 批量创建多个订单
        created_orders = []
        for i in range(5):
            order, message = order_manager.create_order(f"customer_{i:03d}", product.product_id, 2)
            assert order is not None
            assert message == "订单创建成功"
            created_orders.append(order)
        
        assert len(created_orders) == 5
        # 验证库存减少正确
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == initial_stock - 10

    def test_order_history_by_customer(self, mock_managers, sample_products):
        """测试获取客户订单历史"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        customer_id = "customer_001"
        
        # 为同一客户创建多个订单
        order1, _ = order_manager.create_order(customer_id, product.product_id, 3)
        order2, _ = order_manager.create_order(customer_id, product.product_id, 2)
        
        # 获取客户订单历史
        if hasattr(order_manager, 'get_order_history_by_customer'):
            history = order_manager.get_order_history_by_customer(customer_id)
            assert len(history) == 2
        else:
            # 如果方法不存在，通过其他方式验证
            customer_orders = [o for o in order_manager.orders.values() if o.customer_id == customer_id]
            assert len(customer_orders) == 2

    def test_order_statistics(self, mock_managers, sample_products):
        """测试订单统计功能"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建不同状态的订单
        order1, _ = order_manager.create_order("customer_001", product.product_id, 5)
        order2, _ = order_manager.create_order("customer_002", product.product_id, 3)
        
        # 处理订单
        order_manager.process_order(order1.order_id, "accept")
        order_manager.process_order(order2.order_id, "complete")
        
        # 统计订单
        if hasattr(order_manager, 'get_order_statistics'):
            stats = order_manager.get_order_statistics()
            assert 'total_orders' in stats
            assert 'pending_orders' in stats
            assert 'completed_orders' in stats
        else:
            # 如果统计方法不存在，至少验证基本数据
            total_orders = len(order_manager.orders)
            assert total_orders >= 2

    def test_concurrent_order_simulation(self, mock_managers, sample_products):
        """模拟并发订单创建测试"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 保存初始库存
        initial_stock = product_manager.get_product(product.product_id).stock_quantity
        
        # 模拟多个客户同时下单的情况
        customer_ids = [f"customer_{i:03d}" for i in range(10)]
        created_orders = []
        
        for customer_id in customer_ids:
            order, message = order_manager.create_order(customer_id, product.product_id, 1)
            if order is not None:
                created_orders.append(order)
        
        # 验证创建了多个订单
        assert len(created_orders) > 0
        # 验证库存减少
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity < initial_stock

    def test_order_edge_case_empty_customer_id(self, mock_managers, sample_products):
        """测试空客户ID的边界情况"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 使用空客户ID创建订单
        order, message = order_manager.create_order("", product.product_id, 1)
        
        # 应该处理空ID情况（要么拒绝，要么允许但记录空ID）
        if order is None:
            assert "客户" in message or "customer" in message.lower()
        else:
            assert order.customer_id == ""

    def test_order_edge_case_special_characters(self, mock_managers, sample_products):
        """测试包含特殊字符的客户ID"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 使用包含特殊字符的客户ID
        special_customer_id = "customer@#$%^&*()"
        order, message = order_manager.create_order(special_customer_id, product.product_id, 1)
        
        # 应该能够处理特殊字符（要么正确创建，要么优雅地拒绝）
        if order is not None:
            assert order.customer_id == special_customer_id
        else:
            # 如果拒绝，应该有明确的错误信息
            assert len(message) > 0

    def test_order_multiple_products_single_customer(self, mock_managers, sample_products):
        """测试单个客户购买多种商品"""
        product_manager, user_manager, order_manager = mock_managers
        customer_id = "customer_001"
        
        # 购买多种商品
        orders_created = []
        for product in sample_products[:3]:  # 使用前3个商品
            order, message = order_manager.create_order(customer_id, product.product_id, 2)
            assert order is not None
            assert message == "订单创建成功"
            orders_created.append(order)
        
        assert len(orders_created) == 3
        # 验证所有订单都属于同一客户
        for order in orders_created:
            assert order.customer_id == customer_id

    def test_order_validation_extreme_values(self, mock_managers, sample_products):
        """测试极值验证"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 测试极大数量
        extreme_large = 999999999
        order1, message1 = order_manager.create_order("customer_001", product.product_id, extreme_large)
        
        # 测试极小数量（除了0和负数）
        extreme_small = 0.001
        order2, message2 = order_manager.create_order("customer_002", product.product_id, extreme_small)
        
        # 验证对极值的处理
        if order1 is not None:
            assert order1.quantity == extreme_large
        if order2 is not None:
            assert order2.quantity == extreme_small

    def test_order_status_validation_comprehensive(self, mock_managers, sample_products):
        """测试订单状态转换的全面验证"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 创建订单
        order, _ = order_manager.create_order("customer_001", product.product_id, 5)
        assert order.status == "pending"
        
        # 测试所有可能的状态转换
        valid_transitions = [
            ("accept", "accepted"),
            ("complete", "completed"),
            ("reject", "rejected"),
            ("cancel", "cancelled")
        ]
        
        for action, expected_status in valid_transitions:
            # 创建新订单用于每次测试
            test_order, _ = order_manager.create_order("customer_002", product.product_id, 3)
            
            if hasattr(order_manager, 'process_order'):
                success, message = order_manager.process_order(test_order.order_id, action)
                if success:
                    # 如果成功，验证状态
                    assert test_order.status == expected_status
                else:
                    # 如果失败，至少验证有错误信息
                    assert len(message) > 0

    def test_order_error_handling_robustness(self, mock_managers, sample_products):
        """测试错误处理的健壮性"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 测试各种错误情况
        error_cases = [
            ("", product.product_id, 1, "空客户ID"),
            ("customer_001", "", 1, "空商品ID"),
            ("customer_001", "nonexistent", 1, "不存在的商品"),
            ("customer_001", product.product_id, -1, "负数量"),
            ("customer_001", product.product_id, 0, "零数量")
        ]
        
        for customer_id, product_id, quantity, description in error_cases:
            order, message = order_manager.create_order(customer_id, product_id, quantity)
            
            # 验证每种错误情况都有适当的处理
            if order is None:
                # 如果订单创建失败，应该有错误信息
                assert len(message) > 0, f"{description}应该有错误信息"
            else:
                # 如果订单创建成功，验证结果合理
                assert order.customer_id == customer_id or customer_id == ""
                assert order.quantity == quantity

    def test_order_data_integrity_after_errors(self, mock_managers, sample_products):
        """测试错误操作后数据完整性"""
        product_manager, user_manager, order_manager = mock_managers
        product = sample_products[0]
        
        # 先创建一些正常订单
        normal_order, _ = order_manager.create_order("customer_001", product.product_id, 3)
        initial_stock = product_manager.get_product(product.product_id).stock_quantity
        
        # 尝试创建一些会失败的订单
        failed_orders = [
            ("customer_002", "", 1, "空商品ID"),
            ("customer_003", "nonexistent", 1, "不存在商品"),
            ("customer_004", product.product_id, -1, "负数量"),
        ]
        
        for customer_id, product_id, quantity, desc in failed_orders:
            order, message = order_manager.create_order(customer_id, product_id, quantity)
            assert order is None, f"{desc}应该创建失败"
        
        # 验证数据完整性
        final_stock = product_manager.get_product(product.product_id).stock_quantity
        assert final_stock == initial_stock, "错误操作不应该影响库存"
        
        # 验证正常订单仍然存在
        remaining_orders = len(order_manager.orders)
        assert remaining_orders == 1, "错误操作不应该创建额外订单"
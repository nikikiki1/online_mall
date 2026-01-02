import pytest
import os
import tempfile
import json
from unittest.mock import Mock, patch
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.product_manager import ProductManager
from models.product import Product


class TestProductManager:
    """商品管理器全面测试类"""
    
    @pytest.fixture
    def temp_data_dir(self):
        """创建临时数据目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def product_manager(self, temp_data_dir):
        """创建商品管理器实例"""
        data_file = os.path.join(temp_data_dir, "products.json")
        return ProductManager(data_file)
    
    @pytest.fixture
    def sample_products(self, product_manager):
        """创建示例商品"""
        products = []
        test_data = [
            ("iPhone 14", "苹果手机", 5999.0, 50, "merchant_1"),
            ("小米13", "小米手机", 3999.0, 30, "merchant_2"),
            ("华为P60", "华为手机", 5999.0, 20, "merchant_1"),
            ("MacBook Pro", "苹果笔记本", 12999.0, 10, "merchant_1"),
            ("ThinkPad X1", "联想笔记本", 8999.0, 15, "merchant_3"),
        ]
        
        for name, desc, price, stock, merchant_id in test_data:
            product, message = product_manager.create_product(name, desc, price, stock, merchant_id)
            assert product is not None
            assert message == "商品创建成功"
            products.append(product)
        
        return products
    
    def test_product_manager_initialization(self, product_manager):
        """测试商品管理器初始化"""
        assert product_manager is not None
        assert hasattr(product_manager, 'products')
        assert hasattr(product_manager, 'data_file')
        assert isinstance(product_manager.products, dict)
    
    def test_create_product_success(self, product_manager):
        """测试成功创建商品"""
        product, message = product_manager.create_product(
            "测试商品", 
            "测试描述", 
            99.9, 
            100, 
            "merchant_test"
        )
        
        assert product is not None
        assert message == "商品创建成功"
        assert product.name == "测试商品"
        assert product.description == "测试描述"
        assert product.price == 99.9
        assert product.stock_quantity == 100
        assert product.merchant_id == "merchant_test"
        assert product.is_active is True
        assert product.product_id in product_manager.products
    
    def test_create_product_invalid_price_zero(self, product_manager):
        """测试创建商品 - 价格为零"""
        product, message = product_manager.create_product(
            "测试商品", 
            "测试描述", 
            0,  # 价格为零
            100, 
            "merchant_test"
        )
        
        assert product is None
        assert "价格和库存数量必须为正数" in message
        assert len(product_manager.products) == 0
    
    def test_create_product_invalid_price_negative(self, product_manager):
        """测试创建商品 - 负价格"""
        product, message = product_manager.create_product(
            "测试商品", 
            "测试描述", 
            -99.9,  # 负价格
            100, 
            "merchant_test"
        )
        
        assert product is None
        assert "价格和库存数量必须为正数" in message
        assert len(product_manager.products) == 0
    
    def test_create_product_invalid_stock_negative(self, product_manager):
        """测试创建商品 - 负库存"""
        product, message = product_manager.create_product(
            "测试商品", 
            "测试描述", 
            99.9, 
            -100,  # 负库存
            "merchant_test"
        )
        
        assert product is None
        assert "价格和库存数量必须为正数" in message
        assert len(product_manager.products) == 0
    
    def test_create_product_minimal_info(self, product_manager):
        """测试创建商品 - 最少信息"""
        product, message = product_manager.create_product(
            "最少信息商品", 
            "",  # 空描述
            1.0,  # 最小价格
            1,  # 最小库存
            "merchant_min"
        )
        
        assert product is not None
        assert product.name == "最少信息商品"
        assert product.description == ""
        assert product.price == 1.0
        assert product.stock_quantity == 1
        assert product.merchant_id == "merchant_min"
    
    def test_create_product_large_values(self, product_manager):
        """测试创建商品 - 大数值"""
        product, message = product_manager.create_product(
            "大数值商品", 
            "描述", 
            999999.99,  # 大价格
            999999,  # 大库存
            "merchant_large"
        )
        
        assert product is not None
        assert product.price == 999999.99
        assert product.stock_quantity == 999999
    
    def test_get_product_existing(self, product_manager, sample_products):
        """测试获取存在的商品"""
        product = sample_products[0]
        retrieved_product = product_manager.get_product(product.product_id)
        
        assert retrieved_product is not None
        assert retrieved_product.product_id == product.product_id
        assert retrieved_product.name == product.name
        assert retrieved_product.price == product.price
    
    def test_get_product_nonexistent(self, product_manager):
        """测试获取不存在的商品"""
        product = product_manager.get_product("nonexistent_product_id")
        assert product is None
    
    def test_get_product_empty_id(self, product_manager):
        """测试获取空ID的商品"""
        product = product_manager.get_product("")
        assert product is None
    
    def test_get_all_products_empty(self, product_manager):
        """测试获取所有商品 - 空列表"""
        products = product_manager.get_all_products()
        assert isinstance(products, list)
        assert len(products) == 0
    
    def test_get_all_products_with_data(self, product_manager, sample_products):
        """测试获取所有商品 - 有数据"""
        products = product_manager.get_all_products()
        
        assert len(products) == 5  # 所有样本商品都应该是活跃的
        for product in products:
            assert product.is_active is True
    
    def test_get_all_products_after_deactivation(self, product_manager, sample_products):
        """测试获取所有商品 - 部分下架后"""
        # 下架一些商品
        product_manager.toggle_product_status(sample_products[0].product_id, False)
        product_manager.toggle_product_status(sample_products[2].product_id, False)
        
        products = product_manager.get_all_products()
        
        assert len(products) == 3  # 应该有3个活跃商品
        for product in products:
            assert product.is_active is True
    
    def test_get_products_by_merchant_existing(self, product_manager, sample_products):
        """测试按商家获取商品 - 存在商家"""
        merchant_products = product_manager.get_products_by_merchant("merchant_1")
        
        assert len(merchant_products) == 3  # merchant_1有3个商品
        for product in merchant_products:
            assert product.merchant_id == "merchant_1"
    
    def test_get_products_by_merchant_nonexistent(self, product_manager):
        """测试按商家获取商品 - 不存在的商家"""
        merchant_products = product_manager.get_products_by_merchant("nonexistent_merchant")
        
        assert isinstance(merchant_products, list)
        assert len(merchant_products) == 0
    
    def test_get_products_by_merchant_empty_id(self, product_manager):
        """测试按商家获取商品 - 空商家ID"""
        merchant_products = product_manager.get_products_by_merchant("")
        
        assert isinstance(merchant_products, list)
        assert len(merchant_products) == 0
    
    def test_search_products_by_name(self, product_manager, sample_products):
        """测试按名称搜索商品"""
        search_results = product_manager.search_products("iPhone")
        
        assert len(search_results) == 1
        assert "iPhone" in search_results[0].name
    
    def test_search_products_by_description(self, product_manager, sample_products):
        """测试按描述搜索商品"""
        search_results = product_manager.search_products("苹果")
        
        assert len(search_results) == 2  # iPhone和MacBook Pro都包含"苹果"
    
    def test_search_products_nonexistent_keyword(self, product_manager, sample_products):
        """测试搜索商品 - 不存在的关键词"""
        search_results = product_manager.search_products("不存在的关键词")
        
        assert isinstance(search_results, list)
        assert len(search_results) == 0
    
    def test_search_products_empty_keyword(self, product_manager, sample_products):
        """测试搜索商品 - 空关键词"""
        search_results = product_manager.search_products("")
        
        # 应该返回所有活跃商品
        assert len(search_results) == 5
    
    def test_search_products_case_insensitive(self, product_manager, sample_products):
        """测试搜索商品 - 大小写不敏感"""
        search_results_lower = product_manager.search_products("iphone")
        search_results_upper = product_manager.search_products("IPHONE")
        search_results_mixed = product_manager.search_products("iPhOnE")
        
        assert len(search_results_lower) == 1
        assert len(search_results_upper) == 1
        assert len(search_results_mixed) == 1
        assert search_results_lower == search_results_upper == search_results_mixed
    
    def test_search_products_inactive_excluded(self, product_manager, sample_products):
        """测试搜索商品 - 不包含下架商品"""
        # 下架一个商品
        product_manager.toggle_product_status(sample_products[0].product_id, False)
        
        # 搜索包含该商品名称的关键词
        search_results = product_manager.search_products("iPhone")
        
        assert len(search_results) == 0  # 下架的商品不应该被搜索到
    
    def test_update_product_existing_all_fields(self, product_manager, sample_products):
        """测试更新商品信息 - 现有商品，所有字段"""
        product = sample_products[0]
        product_id = product.product_id
        
        success, message = product_manager.update_product(
            product_id,
            name="更新后的商品名称",
            description="更新后的描述",
            price=6999.0
        )
        
        assert success is True
        assert "商品信息已更新" in message
        
        updated_product = product_manager.get_product(product_id)
        assert updated_product.name == "更新后的商品名称"
        assert updated_product.description == "更新后的描述"
        assert updated_product.price == 6999.0
    
    def test_update_product_existing_partial_fields(self, product_manager, sample_products):
        """测试更新商品信息 - 现有商品，部分字段"""
        product = sample_products[0]
        product_id = product.product_id
        original_name = product.name
        original_description = product.description
        
        # 只更新价格
        success, message = product_manager.update_product(
            product_id,
            price=599.0
        )
        
        assert success is True
        assert "商品信息已更新" in message
        
        updated_product = product_manager.get_product(product_id)
        assert updated_product.name == original_name  # 名称不变
        assert updated_product.description == original_description  # 描述不变
        assert updated_product.price == 599.0
    
    def test_update_product_nonexistent(self, product_manager):
        """测试更新商品信息 - 不存在的商品"""
        success, message = product_manager.update_product(
            "nonexistent_product_id",
            name="新名称"
        )
        
        assert success is False
        assert "商品不存在" in message
    
    def test_update_product_price_to_zero(self, product_manager, sample_products):
        """测试更新商品信息 - 价格更新为0"""
        product = sample_products[0]
        
        # 商品模型中的update_info允许价格设为0
        success, message = product_manager.update_product(
            product.product_id,
            price=0
        )
        
        assert success is True
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.price == 0
    
    def test_update_product_negative_price(self, product_manager, sample_products):
        """测试更新商品信息 - 价格更新为负数"""
        product = sample_products[0]
        
        # 商品模型中的update_info不允许负价格
        success, message = product_manager.update_product(
            product.product_id,
            price=-100
        )
        
        assert success is True  # update_info方法本身会验证并忽略负价格
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.price >= 0  # 价格应该保持非负
    
    def test_update_stock_increase(self, product_manager, sample_products):
        """测试更新库存 - 增加库存"""
        product = sample_products[0]
        original_stock = product.stock_quantity
        
        success, message = product_manager.update_stock(product.product_id, 20)
        
        assert success is True
        assert "库存更新成功" in message
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == original_stock + 20
    
    def test_update_stock_decrease(self, product_manager, sample_products):
        """测试更新库存 - 减少库存"""
        product = sample_products[0]
        original_stock = product.stock_quantity
        
        success, message = product_manager.update_stock(product.product_id, -10)
        
        assert success is True
        assert "库存更新成功" in message
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == original_stock - 10
    
    def test_update_stock_nonexistent_product(self, product_manager):
        """测试更新库存 - 不存在的商品"""
        success, message = product_manager.update_stock("nonexistent_product_id", 10)
        
        assert success is False
        assert "商品不存在" in message
    
    def test_update_stock_excessive_decrease(self, product_manager, sample_products):
        """测试更新库存 - 过度减少"""
        product = sample_products[0]
        original_stock = product.stock_quantity
        
        # 尝试减少超过现有库存的数量
        success, message = product_manager.update_stock(product.product_id, -(original_stock + 100))
        
        assert success is False
        assert "库存更新失败" in message
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == original_stock  # 库存应该不变
    
    def test_toggle_product_status_activate(self, product_manager, sample_products):
        """测试商品状态切换 - 上架"""
        product = sample_products[0]
        
        # 先下架
        product_manager.toggle_product_status(product.product_id, False)
        assert product_manager.get_product(product.product_id).is_active is False
        
        # 重新上架
        success, message = product_manager.toggle_product_status(product.product_id, True)
        
        assert success is True
        assert "商品已上架" in message
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.is_active is True
    
    def test_toggle_product_status_deactivate(self, product_manager, sample_products):
        """测试商品状态切换 - 下架"""
        product = sample_products[0]
        assert product.is_active is True
        
        success, message = product_manager.toggle_product_status(product.product_id, False)
        
        assert success is True
        assert "商品已下架" in message
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.is_active is False
    
    def test_toggle_product_status_nonexistent(self, product_manager):
        """测试商品状态切换 - 不存在的商品"""
        success, message = product_manager.toggle_product_status("nonexistent_product_id", True)
        
        assert success is False
        assert "商品不存在" in message
    
    def test_auto_deactivate_zero_stock(self, product_manager, sample_products):
        """测试库存为0时自动下架"""
        product = sample_products[0]
        
        # 将库存减少到0
        success, message = product_manager.update_stock(product.product_id, -product.stock_quantity)
        assert success is True
        
        updated_product = product_manager.get_product(product.product_id)
        assert updated_product.stock_quantity == 0
        assert updated_product.is_active is False  # 应该自动下架
    
    def test_persistence_save_and_load(self, temp_data_dir):
        """测试数据持久化 - 保存和加载"""
        data_file = os.path.join(temp_data_dir, "products.json")
        
        # 创建干净的ProductManager实例
        product_manager1 = ProductManager(data_file)
        
        # 创建一些商品
        products_created = []
        for i in range(3):
            product, message = product_manager1.create_product(
                f"持久化测试商品{i+1}",
                f"描述{i+1}",
                100.0 + i,
                50 + i,
                "merchant_persistence"
            )
            products_created.append(product)
        
        product_ids = [p.product_id for p in products_created]
        
        # 创建新的ProductManager实例来测试加载
        product_manager2 = ProductManager(data_file)
        
        # 验证数据已正确加载
        assert len(product_manager2.products) == 3
        
        for product_id in product_ids:
            loaded_product = product_manager2.get_product(product_id)
            assert loaded_product is not None
            assert loaded_product.product_id == product_id
    
    def test_persistence_load_nonexistent_file(self, temp_data_dir):
        """测试数据持久化 - 加载不存在的文件"""
        data_file = os.path.join(temp_data_dir, "nonexistent_file.json")
        product_manager = ProductManager(data_file)
        
        # 应该能够正常初始化，products为空
        assert isinstance(product_manager.products, dict)
        assert len(product_manager.products) == 0
    
    def test_persistence_load_corrupted_file(self, temp_data_dir):
        """测试数据持久化 - 加载损坏的文件"""
        data_file = os.path.join(temp_data_dir, "corrupted_file.json")
        
        # 创建损坏的JSON文件
        with open(data_file, 'w') as f:
            f.write("{ invalid json content")
        
        # 应该能够正常初始化，忽略损坏的数据
        product_manager = ProductManager(data_file)
        assert isinstance(product_manager.products, dict)
        assert len(product_manager.products) == 0
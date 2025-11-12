import json
import os
from models.product import Product


class ProductManager:
    def __init__(self, data_file=r"d:\软件工程实验\UML\online_mall\data\products.json"):
        self.data_file = data_file
        self.products = {}
        self.load_products()
    
    def load_products(self):
        """从文件加载商品数据"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    products_data = json.load(f)
                    for product_data in products_data:
                        product = Product(
                            product_data['name'],
                            product_data['description'],
                            product_data['price'],
                            product_data['stock_quantity'],
                            product_data['merchant_id']
                        )
                        # 恢复商品ID和其他属性
                        product._product_id = product_data['product_id']
                        product._is_active = product_data['is_active']
                        self.products[product.product_id] = product
            except:
                self.products = {}
    
    def save_products(self):
        """保存商品数据到文件"""
        products_data = []
        for product in self.products.values():
            product_dict = {
                'product_id': product.product_id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'stock_quantity': product.stock_quantity,
                'merchant_id': product.merchant_id,
                'is_active': product.is_active
            }
            products_data.append(product_dict)
        
        # 确保目录存在
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        
        with open(self.data_file, 'w', encoding='utf-8') as f:
            json.dump(products_data, f, ensure_ascii=False, indent=2)
    
    def create_product(self, name, description, price, stock_quantity, merchant_id):
        """创建新商品"""
        if price <= 0 or stock_quantity < 0:
            return None, "价格和库存数量必须为正数"
        
        product = Product(name, description, price, stock_quantity, merchant_id)
        self.products[product.product_id] = product
        self.save_products()
        return product, "商品创建成功"
    
    def get_product(self, product_id):
        """根据ID获取商品"""
        return self.products.get(product_id)
    
    def get_all_products(self):
        """获取所有商品"""
        return [p for p in self.products.values() if p.is_active]
    
    def get_products_by_merchant(self, merchant_id):
        """获取指定商家的所有商品"""
        return [p for p in self.products.values() if p.merchant_id == merchant_id]
    
    def search_products(self, keyword):
        """搜索商品"""
        keyword = keyword.lower()
        results = []
        for product in self.products.values():
            if product.is_active and (
                keyword in product.name.lower() or 
                keyword in product.description.lower()
            ):
                results.append(product)
        return results
    
    def update_product(self, product_id, **kwargs):
        """更新商品信息"""
        product = self.get_product(product_id)
        if not product:
            return False, "商品不存在"
        
        # 更新商品信息
        product.update_info(**kwargs)
        self.save_products()
        return True, "商品信息已更新"
    
    def update_stock(self, product_id, quantity_change):
        """更新库存"""
        product = self.get_product(product_id)
        if not product:
            return False, "商品不存在"
        
        if quantity_change > 0:
            success = product.increase_stock(quantity_change)
        else:
            success = product.decrease_stock(-quantity_change)
        
        if success:
            self.save_products()
            return True, "库存更新成功"
        return False, "库存更新失败"
    
    def toggle_product_status(self, product_id, activate=True):
        """上架或下架商品"""
        product = self.get_product(product_id)
        if not product:
            return False, "商品不存在"
        
        if activate:
            success = product.activate()
            message = "商品已上架" if success else "库存不足，无法上架"
        else:
            product.deactivate()
            success = True
            message = "商品已下架"
        
        if success:
            self.save_products()
            return True, message
        return False, message
from datetime import datetime
import uuid


class Product:
    def __init__(self, name, description, price, stock_quantity, merchant_id):
        self._product_id = str(uuid.uuid4())
        self._name = name
        self._description = description
        self._price = price
        self._stock_quantity = stock_quantity
        self._merchant_id = merchant_id
        self._listing_date = datetime.now()
        self._is_active = True
    
    @property
    def product_id(self):
        return self._product_id
    
    @property
    def name(self):
        return self._name
    
    @property
    def description(self):
        return self._description
    
    @property
    def price(self):
        return self._price
    
    @property
    def stock_quantity(self):
        return self._stock_quantity
    
    @property
    def merchant_id(self):
        return self._merchant_id
    
    @property
    def is_active(self):
        return self._is_active
    
    def update_info(self, name=None, description=None, price=None):
        """更新商品信息"""
        if name:
            self._name = name
        if description:
            self._description = description
        if price is not None and price >= 0:
            self._price = price
        return True
    
    def decrease_stock(self, quantity):
        """减少库存"""
        if quantity <= self._stock_quantity:
            self._stock_quantity -= quantity
            # 检查是否需要自动下架
            self.auto_deactivate()
            return True
        return False
    
    def increase_stock(self, quantity):
        """增加库存"""
        if quantity > 0:
            self._stock_quantity += quantity
            # 如果之前库存为0，现在有库存了，自动上架
            if self._stock_quantity > 0:
                self._is_active = True
            return True
        return False
    
    def auto_deactivate(self):
        """当库存为0时自动下架"""
        if self._stock_quantity <= 0:
            self._is_active = False
            return True
        return False
    
    def activate(self):
        """手动上架商品"""
        if self._stock_quantity > 0:
            self._is_active = True
            return True
        return False
    
    def deactivate(self):
        """手动下架商品"""
        self._is_active = False
        return True
    
    def __str__(self):
        status = "上架" if self._is_active else "下架"
        return f"商品ID: {self._product_id}\n名称: {self._name}\n价格: ¥{self._price}\n库存: {self._stock_quantity}\n状态: {status}"
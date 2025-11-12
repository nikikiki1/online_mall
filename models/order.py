from datetime import datetime
import uuid


class Order:
    def __init__(self, customer_id, product_id, quantity, product_manager):
        self._order_id = str(uuid.uuid4())
        self._customer_id = customer_id
        self._product_id = product_id
        self._quantity = quantity
        self._order_date = datetime.now()
        self._status = "pending"  # pending, accepted, completed, cancelled
        
        # 获取商品信息以计算总金额和商家ID
        product = product_manager.get_product(product_id)
        self._merchant_id = product.merchant_id if product else None
        self._total_amount = product.price * quantity if product else 0
        
        # 关联商品信息（简化版）
        self._product_name = product.name if product else "未知商品"
        self._product_price = product.price if product else 0
    
    @property
    def order_id(self):
        return self._order_id
    
    @property
    def customer_id(self):
        return self._customer_id
    
    @property
    def merchant_id(self):
        return self._merchant_id
    
    @property
    def product_id(self):
        return self._product_id
    
    @property
    def quantity(self):
        return self._quantity
    
    @property
    def total_amount(self):
        return self._total_amount
    
    @property
    def status(self):
        return self._status
    
    @property
    def price(self):
        return self._product_price
    
    @property
    def order_date(self):
        return self._order_date
    
    def calculate_total(self):
        """计算订单总金额"""
        return self._total_amount
    
    def update_status(self, new_status):
        """更新订单状态"""
        valid_statuses = ["pending", "accepted", "completed", "cancelled"]
        if new_status in valid_statuses:
            self._status = new_status
            return True
        return False
    
    def complete(self):
        """标记订单完成"""
        return self.update_status("completed")
    
    def cancel(self):
        """取消订单"""
        return self.update_status("cancelled")
    
    def accept(self):
        """接受订单"""
        return self.update_status("accepted")
    
    def __str__(self):
        status_map = {
            "pending": "待处理",
            "accepted": "已接单",
            "completed": "已完成",
            "cancelled": "已取消"
        }
        return (f"订单ID: {self._order_id}\n" 
                f"商品: {self._product_name}\n" 
                f"数量: {self._quantity}\n" 
                f"单价: ¥{self._product_price}\n" 
                f"总金额: ¥{self._total_amount}\n" 
                f"状态: {status_map.get(self._status, self._status)}\n" 
                f"下单时间: {self._order_date.strftime('%Y-%m-%d %H:%M:%S')}")
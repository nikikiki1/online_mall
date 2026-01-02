import uuid
from datetime import datetime
from typing import Optional, Union
from models.product import Product
from services.product_manager import ProductManager


class Order:
    def __init__(self, customer_id: str, product_id: str, quantity: int, product_manager: Optional[ProductManager] = None):
        self._order_id: str = str(uuid.uuid4())
        self._customer_id: str = customer_id
        self._product_id: str = product_id
        self._quantity: int = quantity
        self._order_date: datetime = datetime.now()
        self._status: str = "pending"  # pending, accepted, completed, cancelled
        
        # 获取商品信息以计算总金额和商家ID
        self._product_manager = product_manager
        self._initial_product_price: float = 0.0  # 存储订单创建时的价格
        
        # 如果有ProductManager，验证商品存在并获取初始价格
        if product_manager:
            product = product_manager.get_product(product_id)
            if product:
                self._merchant_id = product.merchant_id
                self._initial_product_price = product.price
                self._total_amount = self._initial_product_price * quantity
            else:
                self._merchant_id = None
                self._total_amount = 0.0
        else:
            self._merchant_id = None
            self._total_amount = 0.0
    
    @property
    def order_id(self) -> str:
        return self._order_id
    
    @property
    def customer_id(self) -> str:
        return self._customer_id
    
    @property
    def merchant_id(self) -> Optional[str]:
        return self._merchant_id
    
    @property
    def product_id(self) -> str:
        return self._product_id
    
    @property
    def quantity(self) -> int:
        return self._quantity
    
    @property
    def total_amount(self) -> float:
        return self._total_amount
    
    @property
    def status(self) -> str:
        return self._status
    
    @property
    def product_name(self) -> str:
        """动态获取商品名称"""
        if self._product_manager:
            product = self._product_manager.get_product(self._product_id)
            return product.name if product else "未知商品"
        return "未知商品"
    
    @property
    def product_price(self) -> float:
        """动态获取商品价格"""
        if self._product_manager:
            product = self._product_manager.get_product(self._product_id)
            return product.price if product else 0.0
        return 0.0
    
    def refresh_product_info(self) -> None:
        """刷新商品信息"""
        if self._product_manager:
            product = self._product_manager.get_product(self._product_id)
            if product:
                self._merchant_id = product.merchant_id
    
    @property
    def price(self) -> float:
        """动态获取商品价格"""
        if self._product_manager:
            product = self._product_manager.get_product(self._product_id)
            return product.price if product else 0.0
        return 0.0
    
    @property
    def order_date(self) -> datetime:
        return self._order_date
    
    def calculate_total(self) -> float:
        """计算订单总金额"""
        return self._total_amount
    
    def update_status(self, new_status: str) -> bool:
        """更新订单状态"""
        valid_transitions = {
            "pending": ["accepted", "cancelled", "rejected"],
            "accepted": ["completed"],
            "completed": [],
            "cancelled": [],
            "rejected": []
        }
        
        if new_status not in ["pending", "accepted", "completed", "cancelled", "rejected"]:
            return False
        
        if new_status in valid_transitions.get(self._status, []):
            self._status = new_status
            return True
        
        return False
    
    def complete(self) -> bool:
        """标记订单完成"""
        return self.update_status("completed")
    
    def cancel(self) -> bool:
        """取消订单"""
        return self.update_status("cancelled")
    
    def reject(self) -> bool:
        """拒绝订单"""
        return self.update_status("rejected")
    
    def accept(self) -> bool:
        """接受订单"""
        return self.update_status("accepted")
    
    def __str__(self) -> str:
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
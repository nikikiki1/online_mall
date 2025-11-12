from abc import ABC, abstractmethod
from datetime import datetime
import uuid


class User(ABC):
    def __init__(self, username, password, email, role):
        self._user_id = str(uuid.uuid4())
        self._username = username
        self._password = password  # 实际应用中应加密存储
        self._email = email
        self._role = role
        self._registration_date = datetime.now()
    
    @property
    def user_id(self):
        return self._user_id
    
    @property
    def username(self):
        return self._username
    
    @property
    def email(self):
        return self._email
    
    @property
    def role(self):
        return self._role
    
    def register(self):
        """注册用户"""
        # 实际应用中应该有更多的验证逻辑
        return True
    
    def login(self, username, password):
        """用户登录"""
        return self._username == username and self._password == password
    
    def logout(self):
        """用户登出"""
        print(f"用户 {self._username} 已登出")


class Merchant(User):
    def __init__(self, username, password, email, shop_name, contact_info):
        super().__init__(username, password, email, "merchant")
        self._merchant_id = self._user_id  # 商家ID与用户ID相同
        self._shop_name = shop_name
        self._contact_info = contact_info
    
    @property
    def merchant_id(self):
        return self._merchant_id
    
    @property
    def shop_name(self):
        return self._shop_name
    
    @property
    def contact_info(self):
        return self._contact_info
    
    def add_product(self, product_manager, name, description, price, stock_quantity):
        """添加商品"""
        return product_manager.create_product(name, description, price, stock_quantity, self._merchant_id)
    
    def manage_products(self, product_manager):
        """管理商品"""
        return product_manager.get_products_by_merchant(self._merchant_id)
    
    def process_order(self, order_manager, order_id, action):
        """处理订单"""
        order = order_manager.get_order(order_id)
        if order and order.merchant_id == self._merchant_id:
            return order.update_status(action)
        return False
    
    def view_inventory(self, product_manager):
        """查看库存"""
        return self.manage_products(product_manager)


class Customer(User):
    def __init__(self, username, password, email, shipping_address, phone_number):
        super().__init__(username, password, email, "customer")
        self._customer_id = self._user_id  # 顾客ID与用户ID相同
        self._shipping_address = shipping_address
        self._phone_number = phone_number
    
    @property
    def customer_id(self):
        return self._customer_id
    
    @property
    def shipping_address(self):
        return self._shipping_address
    
    @property
    def phone_number(self):
        return self._phone_number
    
    def browse_products(self, product_manager):
        """浏览商品"""
        return product_manager.get_all_products()
    
    def search_products(self, product_manager, keyword):
        """搜索商品"""
        return product_manager.search_products(keyword)
    
    def place_order(self, order_manager, product_id, quantity):
        """下单购买"""
        return order_manager.create_order(self._customer_id, product_id, quantity)
    
    def contact_seller(self, order_manager, order_id):
        """联系卖家"""
        return order_manager.exchange_contact_info(order_id)
    
    def view_purchases(self, order_manager):
        """查看购买记录"""
        return order_manager.get_orders_by_customer(self._customer_id)
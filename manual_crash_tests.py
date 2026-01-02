#!/usr/bin/env python3
"""
手动构造的崩溃测试用例
用于演示模糊测试发现的潜在崩溃场景
"""

import os
import sys
import tempfile
import traceback
import json
import time
from datetime import datetime

with open("test_crashes.log", "w", encoding="utf-8") as crash_log:
    def log_crash(test_name, error_msg, traceback_info):
        """记录崩溃信息到日志文件"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        crash_info = f"""
{'='*50}
崩溃测试: {test_name}
时间: {timestamp}
错误信息: {error_msg}
追踪信息:
{traceback_info}
{'='*50}
"""
        print(crash_info)
        crash_log.write(crash_info)
        crash_log.flush()

def test_user_manager_crashes():
    """测试UserManager的崩溃场景"""
    print("\n=== UserManager 崩溃测试 ===")
    
    # 测试1: 无效文件路径
    try:
        from services.user_manager import UserManager
        invalid_paths = [
            "/invalid/path/users.json",
            "../../../etc/passwd",
            "/root/.ssh/id_rsa",
            "",  # 空路径
            None,  # None路径
        ]
        
        for path in invalid_paths:
            try:
                user_manager = UserManager(data_file=path)
                user_manager.register_user("test", "test", "test@test.com", "customer")
            except Exception as e:
                log_crash("无效文件路径测试", str(e), traceback.format_exc())
    except ImportError as e:
        log_crash("导入UserManager失败", str(e), "")
    
    # 测试2: 恶意JSON文件
    malicious_jsons = [
        '{"__reduce__": ["os.system", ["echo hacked"]]}',  # pickle反序列化
        '{"a": "A" * 100000000}',  # 巨大JSON
        '{"malicious": "\x00\x01\x02"}',  # 包含控制字符
        'not json at all',  # 无效JSON
        '',  # 空文件
        'null',  # 无效的根类型
    ]
    
    for i, malicious_json in enumerate(malicious_jsons):
        try:
            tmp_file = tempfile.mktemp(suffix=f'_malicious_{i}.json')
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write(malicious_json)
            
            user_manager = UserManager(data_file=tmp_file)
            user_manager.load_users()  # 强制加载恶意JSON
            os.unlink(tmp_file)
        except Exception as e:
            log_crash(f"恶意JSON测试 {i}", str(e), traceback.format_exc())
    
    # 测试3: 内存不足模拟（大量用户注册）
    try:
        user_manager = UserManager(data_file=None)
        # 注册大量用户直到可能触发内存问题
        for i in range(10000):  # 减少数量避免实际内存问题
            try:
                user_manager.register_user(
                    f"user_{i}_" + "A" * 1000,  # 长用户名
                    "password", 
                    f"user{i}@test.com", 
                    "customer"
                )
            except Exception as e:
                log_crash(f"大量用户注册测试 {i}", str(e), traceback.format_exc())
                break
    except Exception as e:
        log_crash("大量用户注册初始化失败", str(e), traceback.format_exc())

def test_product_manager_crashes():
    """测试ProductManager的崩溃场景"""
    print("\n=== ProductManager 崩溃测试 ===")
    
    try:
        from services.product_manager import ProductManager
        
        # 测试1: 无效数值
        invalid_products = [
            (None, "description", 10.0, 100, "merchant1"),  # None名称
            ("product", None, 10.0, 100, "merchant1"),      # None描述
            ("product", "description", float('inf'), 100, "merchant1"),  # 无穷大价格
            ("product", "description", float('nan'), 100, "merchant1"),  # NaN价格
            ("product", "description", 10.0, float('inf'), "merchant1"), # 无穷大库存
            ("product", "description", 10.0, -999999999999999999, "merchant1"), # 负库存
        ]
        
        for name, desc, price, stock, merchant_id in invalid_products:
            try:
                product_manager = ProductManager(data_file=None)
                product_manager.create_product(name, desc, price, stock, merchant_id)
            except Exception as e:
                log_crash("无效商品参数测试", f"name={name}, desc={desc}, price={price}, stock={stock}", traceback.format_exc())
        
        # 测试2: 超长商品数据
        try:
            product_manager = ProductManager(data_file=None)
            product_manager.create_product(
                "A" * 100000,  # 超长名称
                "B" * 1000000, # 超长描述
                999999999999999, # 极大价格
                999999999999999, # 极大库存
                "merchant_id_" + "C" * 10000  # 超长商户ID
            )
        except Exception as e:
            log_crash("超长商品数据测试", str(e), traceback.format_exc())
            
    except ImportError as e:
        log_crash("导入ProductManager失败", str(e), "")

def test_order_manager_crashes():
    """测试OrderManager的崩溃场景"""
    print("\n=== OrderManager 崩溃测试 ===")
    
    try:
        from services.order_manager import OrderManager
        from services.user_manager import UserManager
        from services.product_manager import ProductManager
        
        # 先创建必要的依赖
        user_manager = UserManager(data_file=None)
        product_manager = ProductManager(data_file=None)
        order_manager = OrderManager(product_manager, user_manager, data_file=None)
        
        # 测试1: 无效订单参数
        invalid_orders = [
            (None, None, None),                    # 全None
            ("", "", 0),                          # 空字符串和零
            ("user_id", "product_id", float('inf')), # 无穷大数量
            ("user_id", "product_id", -999999999999999), # 负数量
            ("A" * 100000, "B" * 100000, 1),      # 超长ID
        ]
        
        for user_id, product_id, quantity in invalid_orders:
            try:
                order_manager.create_order(user_id, product_id, quantity)
            except Exception as e:
                log_crash("无效订单参数测试", f"user_id={user_id}, product_id={product_id}, quantity={quantity}", traceback.format_exc())
        
        # 测试2: 订单处理崩溃
        invalid_order_ids = [
            None,
            "",
            "A" * 100000,
            "../../../etc/passwd",
            "\x00\x01\x02",
        ]
        
        for order_id in invalid_order_ids:
            try:
                order_manager.process_order(order_id, "complete")
                order_manager.get_order(order_id)
                order_manager.exchange_contact_info(order_id)
            except Exception as e:
                log_crash("无效订单ID测试", f"order_id={repr(order_id)}", traceback.format_exc())
        
        # 测试3: 恶意操作字符串
        malicious_actions = [
            "../../../bin/sh",  # 路径遍历
            "\x00rm -rf /",     # 注入攻击
            "A" * 100000,      # 超长操作
            None,               # None操作
        ]
        
        for action in malicious_actions:
            try:
                order_manager.process_order("test_order_id", action)
            except Exception as e:
                log_crash("恶意操作测试", f"action={repr(action)}", traceback.format_exc())
                
    except ImportError as e:
        log_crash("导入OrderManager失败", str(e), "")

def test_concurrent_access_crashes():
    """测试并发访问导致的崩溃"""
    print("\n=== 并发访问崩溃测试 ===")
    
    import threading
    import time
    
    def concurrent_user_registration():
        """并发用户注册"""
        try:
            from services.user_manager import UserManager
            user_manager = UserManager(data_file=None)
            
            for i in range(100):
                try:
                    user_manager.register_user(
                        f"thread_{threading.current_thread().name}_{i}",
                        "password",
                        f"thread_{i}@test.com",
                        "customer"
                    )
                except Exception as e:
                    log_crash("并发用户注册", f"线程 {threading.current_thread().name}: {str(e)}", traceback.format_exc())
        except Exception as e:
            log_crash("并发测试初始化失败", str(e), traceback.format_exc())
    
    # 创建多个线程并发注册用户
    threads = []
    for i in range(10):
        thread = threading.Thread(target=concurrent_user_registration, name=f"UserReg-{i}")
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()

def test_file_system_crashes():
    """测试文件系统相关的崩溃"""
    print("\n=== 文件系统崩溃测试 ===")
    
    # 测试1: 只读文件系统
    try:
        readonly_file = "/proc/sys/kernel/hostname"  # 通常是只读的
        from services.user_manager import UserManager
        user_manager = UserManager(data_file=readonly_file)
        user_manager.register_user("test", "test", "test@test.com", "customer")
    except Exception as e:
        log_crash("只读文件系统测试", str(e), traceback.format_exc())
    
    # 测试2: 磁盘空间不足模拟
    try:
        large_file = tempfile.mktemp(suffix='_large.json')
        with open(large_file, 'w') as f:
            f.write('[' + '{"test": "A" * 100000000}' * 10000 + ']')  # 写一个大文件
        
        from services.user_manager import UserManager
        user_manager = UserManager(data_file=large_file)
        user_manager.load_users()
        os.unlink(large_file)
    except Exception as e:
        log_crash("大文件测试", str(e), traceback.format_exc())
        try:
            os.unlink(large_file)
        except:
            pass

def test_gui_crashes():
    """测试GUI相关的崩溃场景"""
    print("\n=== GUI崩溃测试 ===")
    
    try:
        # 检查是否有显示环境
        if os.environ.get('DISPLAY') is None:
            print("跳过GUI测试 - 没有DISPLAY环境变量")
            return
            
        # 测试tkinter相关的崩溃（如果GUI组件存在）
        import tkinter as tk
        from tkinter import messagebox
        
        root = tk.Tk()
        root.withdraw()  # 隐藏窗口
        
        # 测试无效的tkinter操作
        invalid_widgets = [
            None,  # None控件
            "invalid_widget",  # 字符串而不是控件
            123,   # 数字而不是控件
        ]
        
        for widget in invalid_widgets:
            try:
                if hasattr(widget, 'winfo_class'):
                    widget.update()
                elif widget is None:
                    widget.update()  # 这会导致AttributeError
            except Exception as e:
                log_crash("无效tkinter控件测试", f"widget={repr(widget)}", traceback.format_exc())
        
        root.destroy()
        
    except ImportError:
        log_crash("tkinter导入失败", "tkinter模块不可用", "")
    except Exception as e:
        log_crash("GUI测试失败", str(e), traceback.format_exc())

def main():
    """运行所有崩溃测试"""
    print("开始运行手动构造的崩溃测试用例...")
    
    # 创建日志文件
    test_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("test_crashes.log", "w", encoding="utf-8") as f:
        f.write(f"崩溃测试开始时间: {test_start_time}\n")
        f.write("=" * 80 + "\n")
    
    try:
        test_user_manager_crashes()
        test_product_manager_crashes()
        test_order_manager_crashes()
        test_concurrent_access_crashes()
        test_file_system_crashes()
        test_gui_crashes()
        
        test_end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("test_crashes.log", "a", encoding="utf-8") as f:
            f.write(f"\n崩溃测试结束时间: {test_end_time}\n")
        
        print(f"\n所有崩溃测试完成！结果已记录到 test_crashes.log")
        
    except Exception as e:
        print(f"崩溃测试过程中出现严重错误: {e}")
        with open("test_crashes.log", "a", encoding="utf-8") as f:
            f.write(f"\n严重错误: {str(e)}\n")
            f.write(traceback.format_exc())

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
ProductManager 模糊测试 - 测试商品管理和库存功能
"""

import os
import sys
import tempfile
import atheris

with atheris.instrument_imports():
    from services.product_manager import ProductManager

def TestOneInput(data):
    """ProductManager 模糊测试入口函数"""
    fdp = atheris.FuzzedDataProvider(data)
    
    # 创建临时文件用于测试
    tmp_file = tempfile.mktemp(suffix='_fuzz_products.json')
    try:
        with open(tmp_file, 'w') as f:
            f.write('[]')
        
        test_manager = ProductManager(data_file=tmp_file)
        
        # 测试商品创建功能
        try:
            name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            description = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 200))
            price = fdp.ConsumeFloat()  # 允许负数和特殊浮点数
            stock_quantity = fdp.ConsumeIntInRange(-1000, 1000)  # 允许负数测试边界情况
            merchant_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            
            test_manager.create_product(name, description, price, stock_quantity, merchant_id)
        except Exception:
            pass
        
        # 测试商品查找功能
        try:
            product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            test_manager.get_product(product_id)
        except Exception:
            pass
        
        # 测试商品搜索功能
        try:
            keyword = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            test_manager.search_products(keyword)
        except Exception:
            pass
        
        # 测试商家商品查询
        try:
            merchant_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            test_manager.get_products_by_merchant(merchant_id)
        except Exception:
            pass
        
        # 测试商品更新功能
        try:
            product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            
            # 生成随机更新参数
            name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 100))
            description = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 200))
            price = fdp.ConsumeFloat()
            
            test_manager.update_product(product_id, name=name, description=description, price=price)
        except Exception:
            pass
        
        # 测试库存更新功能
        try:
            product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            quantity_change = fdp.ConsumeIntInRange(-1000, 1000)
            
            test_manager.update_stock(product_id, quantity_change)
        except Exception:
            pass
        
        # 测试商品状态切换功能
        try:
            product_id = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            activate = fdp.PickValueInList([True, False])
            
            test_manager.toggle_product_status(product_id, activate)
        except Exception:
            pass
        
        # 测试获取所有商品功能
        try:
            test_manager.get_all_products()
        except Exception:
            pass
            
    finally:
        try:
            os.unlink(tmp_file)
        except:
            pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
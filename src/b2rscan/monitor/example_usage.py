#!/usr/bin/env python3
"""
日志功能使用示例
"""

import logging
from b2rscan.monitor.logging import log_json

def main():
    """
    演示如何使用日志功能
    """
    
    # 基本日志记录
    log_json(logging.INFO, "应用程序启动")
    
    # 带有额外数据的日志记录
    log_json(logging.INFO, "处理用户请求", 
             user_id=12345, 
             action="login", 
             ip_address="192.168.1.1")
    
    # 错误日志记录
    try:
        result = 10 / 0
    except ZeroDivisionError as e:
        log_json(logging.ERROR, "除零错误", 
                 error=str(e), 
                 operation="division", 
                 operands=[10, 0])
    
    # 调试信息
    log_json(logging.DEBUG, "调试信息", 
             variable_a="value_a", 
             variable_b="value_b", 
             step="initialization")
    
    log_json(logging.INFO, "应用程序正常结束")

if __name__ == "__main__":
    main()
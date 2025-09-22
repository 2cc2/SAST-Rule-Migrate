# -*- coding: utf-8 -*-
"""
代理适配器模块
该模块负责与不同SAST工具的代理进行交互
"""

import os
import sys

# 将trae-agent添加到路径中
trae_agent_path = os.path.join(os.path.dirname(__file__), 'trae-agent')
if trae_agent_path not in sys.path:
    sys.path.insert(0, trae_agent_path)

# 延迟导入，避免在模块加载时就导入所有依赖
def get_trae_agent():
    """
    获取trae-agent实例
    
    Returns:
        trae-agent相关类和函数
    """
    try:
        from trae_agent.agent.agent import Agent, AgentType
        from trae_agent.utils.config import Config
        return Agent, AgentType, Config
    except ImportError:
        raise ImportError("无法导入trae-agent，请检查agent_adapter/trae-agent目录")

__all__ = ['get_trae_agent']
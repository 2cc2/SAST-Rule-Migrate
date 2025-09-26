# SAST 工具理解模块

## 概述

SAST 工具理解模块是 B2RScan 的核心组件之一，负责深入分析和理解各种 SAST 工具的内部工作机制。通过智能代理和知识图谱技术，该模块能够构建对 SAST 工具架构、规则加载机制和分析流程的全面认知。

## 功能特性

### 1. 智能代理分析
- 使用 ReAct（Reasoning + Action）模式逐步探索 SAST 工具
- 自动分析代码库结构和组织方式
- 识别关键组件和配置文件

### 2. 知识图谱构建
- 构建和维护 SAST 工具的结构化知识表示
- 记录工具的架构、规则格式和执行机制
- 支持增量更新和持续学习

### 3. 多工具支持
- 支持多种主流 SAST 工具（CodeQL、Semgrep 等）
- 统一的分析框架，可扩展支持新工具
- 工具特定的分析策略和方法

## 工作原理

SAST 工具理解模块遵循以下工作流程：

1. **初始化阶段**
   - 创建智能代理实例
   - 加载配置和工具注册表
   - 初始化知识图谱

2. **探索阶段**
   - 分析代码库目录结构
   - 识别配置文件和主要组件
   - 理解工具的组织方式

3. **深入分析阶段**
   - 研究规则加载和解析机制
   - 分析执行引擎和分析流程
   - 识别关键数据结构和接口

4. **知识整合阶段**
   - 将发现的信息整合到知识图谱
   - 持续更新和完善知识表示
   - 生成最终的理解报告

## 核心组件

### SASTUnderstandAgent
主要的智能代理类，负责协调整个理解过程。

```python
class SASTUnderstandAgent:
    def __init__(self, sast_code_path, sast_name: Optional[str]=None):
        # 初始化代理
        
    def run(self, user_task: Optional[str] = None):
        # 执行理解任务
```

### 知识图谱
用于存储和管理对 SAST 工具的理解结果。

### 工具注册表
管理可用的工具函数，支持代理执行各种操作。

## 使用方法

### 基本用法

```python
from b2rscan.task.understanding.agent import SASTUnderstandAgent

# 创建代理实例
agent = SASTUnderstandAgent("/path/to/sast/code", "sast_name")

# 运行理解任务
agent.run()
```

### 自定义任务

```python
# 提供自定义任务描述
custom_task = "请重点分析该SAST工具的规则加载机制和执行流程"
agent.run(custom_task)
```

## 知识图谱持久化

根据规范，理解模块会在以下情况下持久化知识图谱：

1. 任务完成时（action 为 "finish"）
2. 达到最大步骤数时
3. 知识图谱会保存为 JSON 格式文件
4. 文件命名为 `{SAST工具名称}_knowledge_graph.json`
5. 默认存储在 `agent_output/` 目录下

## ReAct 模式

理解代理采用 ReAct 模式进行工作：

```
思考(Thought) -> 行动(Action) -> 观察(Observation)
```

该循环持续进行，直到代理认为已全面掌握 SAST 工具的工作原理。

### 支持的工具函数

代理可以调用多种工具函数来执行操作，如：
- 文件系统操作（读取文件、列出目录）
- 代码分析工具
- 执行命令行工具

## 配置

理解模块的相关配置位于 [config.yaml](../config.yaml)：

```yaml
sast_understanding:
    knowledge_graph_dir: "sast_knowledge_graph"  # 知识图谱存储目录
    max_steps: 20                                # 最大执行步骤数
```

## 扩展支持

要添加对新 SAST 工具的支持，可以：

1. 实现工具特定的分析策略
2. 添加新的工具函数
3. 扩展知识图谱结构以适应新工具的特点

## 最佳实践

### 理解目标优先级
优先深入理解 SAST 工具的内部运作机理，如：
- 规则加载方式
- 架构组件
- 分析执行流程

而不是直接进行规则提取。

### 知识管理
在理解过程中持续构建和维护知识图谱，记录认知进展。

### 终止条件
仅当代理认为已全面掌握 SAST 工具的工作原理后方可结束任务。
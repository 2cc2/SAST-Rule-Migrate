import json
import os
import re
from typing import Optional, Dict, Any, List
from b2rscan.llm_wrapper import LLMWrapper
from b2rscan.toolbox.tool_registry import ToolRegistry
from b2rscan.config.config_loader import ConfigLoader
from b2rscan.task.understanding.specification import *
from b2rscan.monitor.logging import *

class SASTUnderstandAgent:
    """Understand Agent for SAST tools."""
    
    def __init__(self, sast_code_path, sast_name: Optional[str]=None):
        self.system_prompt = SYSTEM_PROMPT
        self.llm_client = LLMWrapper("dashscope")
        self.sast_name = sast_name
        self.sast_code_path = sast_code_path
        self.tools = ToolRegistry()
        self.knowledge_graph = {}
        self.current_step = 0
        self._load_config()

    def _load_config(self):
        self.config = ConfigLoader().config_data
        self.max_steps = self.config["sast_understanding"]["max_steps"]
        self.knowledge_graph_dir = self.config["sast_understanding"]["knowledge_graph_dir"]


    def _compose_prompt(self, user_task: str):
        return self.system_prompt.format(
            tool_specs=self.tools.tool_specs_for_prompt(),
            user_task=user_task
        )
    
    def _get_function_definitions(self) -> List[Dict[str, Any]]:
        """获取工具函数定义，用于函数调用"""
        functions = []
        for tool_name, tool in self.tools._tools.items():
            functions.append({
                "name": tool_name,
                "description": tool.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        # 这里可以添加更具体的参数定义
                    },
                    "required": []
                }
            })
        # 添加finish函数
        functions.append({
            "name": "finish",
            "description": "Finish the task and save the knowledge graph",
            "parameters": {
                "type": "object",
                "properties": {
                    "knowledge_update": {
                        "type": "object",
                        "description": "Final knowledge to update in the knowledge graph"
                    }
                },
                "required": []
            }
        })
        return functions
    
    def _update_knowledge_graph(self, knowledge_update):
        """更新知识图谱"""
        if knowledge_update and isinstance(knowledge_update, dict):
            # 简单的合并策略，实际应用中可能需要更复杂的合并逻辑
            def deep_merge(dict1, dict2):
                for key, value in dict2.items():
                    if key in dict1 and isinstance(dict1[key], dict) and isinstance(value, dict):
                        deep_merge(dict1[key], value)
                    else:
                        dict1[key] = value
                return dict1
            
            self.knowledge_graph = deep_merge(self.knowledge_graph, knowledge_update)

    def _save_knowledge_graph(self):

        os.makedirs(self.knowledge_graph_dir, exist_ok=True)
        
        filename = f"{self.sast_name}_knowledge_graph.json"
        filepath = os.path.join(self.knowledge_graph_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.knowledge_graph, f, indent=2, ensure_ascii=False)
        
        print(f"Knowledge graph saved to {filepath}")

    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """
        从LLM响应中提取并解析JSON对象
        
        Args:
            response: LLM的原始响应
            
        Returns:
            解析后的JSON对象
        """
        # 方法1: 尝试直接解析整个响应
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # 方法2: 查找第一个完整的JSON对象
        # 使用正则表达式匹配可能的JSON对象
        json_pattern = r'\{(?:[^{}]|(?R))*\}'
        matches = re.findall(json_pattern, response, re.DOTALL)
        
        for match in matches:
            try:
                obj = json.loads(match)
                # 验证是否包含必要的字段
                if all(key in obj for key in ["thought", "action", "action_input"]):
                    return obj
            except json.JSONDecodeError:
                continue
        
        # 方法3: 原有的方法，查找第一个{和最后一个}
        try:
            first_brace = response.find("{")
            last_brace = response.rfind("}")
            if first_brace != -1 and last_brace != -1 and first_brace < last_brace:
                json_str = response[first_brace:last_brace+1]
                obj = json.loads(json_str)
                # 验证是否包含必要的字段
                if all(key in obj for key in ["thought", "action", "action_input"]):
                    return obj
        except json.JSONDecodeError:
            pass
        
        # 如果所有方法都失败，返回默认对象
        return {
            "thought": "Failed to parse response",
            "action": "finish",
            "action_input": {},
            "knowledge_update": {}
        }

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """
        解析LLM响应，支持多种格式
        
        Args:
            response: LLM的原始响应
            
        Returns:
            解析后的动作对象
        """
        # 尝试作为JSON直接解析
        try:
            action_obj = json.loads(response)
            if isinstance(action_obj, dict) and "action" in action_obj:
                return action_obj
        except:
            pass
        
        # 尝试提取JSON片段
        return self._extract_json_from_response(response)

    def run(self, user_task: Optional[str] = None):
        if not user_task:
            user_task = f"Understand how the {self.sast_name} SAST tool works internally. Explore the codebase at {self.sast_code_path} and build a comprehensive knowledge graph of its architecture, rule loading mechanisms, and analysis process."
        
        self.user_task = user_task
        scratch = ""
        
        # 获取函数定义
        function_definitions = self._get_function_definitions()
        
        for step in range(1, self.max_steps + 1):
            self.current_step = step
            prompt = self._compose_prompt(user_task=self.user_task) + "\n\nCurrent knowledge:\n" + json.dumps(self.knowledge_graph, indent=2, ensure_ascii=False) + "\n\nPrevious actions:\n" + scratch
            
            # 使用函数调用
            raw_response = self.llm_client.infer(prompt, functions=function_definitions)
            
            # 解析响应，使用更鲁棒的方法
            try:
                action_obj = self._parse_llm_response(raw_response)
            except Exception as e:
                print(f"Error parsing LLM response: {e}")
                action_obj = {
                    "thought": "Failed to parse response, trying again...",
                    "action": "finish",
                    "action_input": {},
                    "knowledge_update": {}
                }
            
            thought = action_obj.get("thought", "")
            action = action_obj.get("action", "")
            action_input = action_obj.get("action_input", {})
            knowledge_update = action_obj.get("knowledge_update", {})
            
            # 更新知识图谱
            self._update_knowledge_graph(knowledge_update)
            
            # 如果是结束动作
            if action == "finish":
                print(f"Finished understanding {self.sast_name} after {step} steps.")
                # 保存知识图谱到文件
                self._save_knowledge_graph()
                break
            
            # 执行工具调用
            observation = ""
            if self.tools.has(action):
                try:
                    tool = self.tools.get(action)
                    tool_result = tool.run(**action_input)
                    observation = tool_result.content if tool_result.ok else f"ERROR: {tool_result.error}"
                except Exception as e:
                    observation = f"ERROR: Exception during tool execution: {str(e)}"
            else:
                observation = f"ERROR: Unknown tool '{action}'"
            
            # 更新执行历史
            scratch += f"\nStep {step}:\nTHOUGHT: {thought}\nACTION: {action}\nOBSERVATION: {str(observation)}\n"
            
            # 如果执行了很多步但没有进展，可以考虑结束
            if step >= self.max_steps:
                print(f"Reached maximum steps ({self.max_steps}) for understanding {self.sast_name}.")
                # 保存知识图谱到文件
                self._save_knowledge_graph()
        
        # 不再返回知识图谱，而是保存到文件
        return f"Knowledge graph for {self.sast_name} has been saved to {self.output_dir} directory."


if __name__ == "__main__":
    agent = SASTUnderstandAgent("sast/codeql", "codeql")
    agent.run()
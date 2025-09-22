

class Agent:
    def __init__(self, agent_type:str = "min_agent") -> None:
        self.agent = self._get_agent(agent_type)

    
    def _get_agent(self, agent_type):
        if agent_type == "min_agent":
            from b2rscan.agent_wrapper.min_agent import MinAgent
            return MinAgent()
        else:
            raise ValueError(f"Invalid agent type: {agent_type}")

    def run(self, task: str):
        self.agent.new_task(task)
        execution = self.agent.execute_task()
        return execution
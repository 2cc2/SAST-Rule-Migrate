
class Agent:
    def __init__(self, agent_type) -> None:
        self.agent = self._get_agent(agent_type)

    
    def _get_agent(self, agent_type):
        if agent_type == "min_agent":
            from b2rscan.agent_wrapper.min_agent import MinAgent
            return MinAgent()
        elif agent_type == "trae_agent":
            from trae_agent.agent.trae_agent import TraeAgent
            return TraeAgent()
        else:
            raise ValueError(f"Invalid agent type: {agent_type}")

    def run(self, task: str):
        self.agent.
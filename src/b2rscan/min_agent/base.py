from abc import ABC

class BaseAgent(ABC):
    def __init__(self) -> None:
        super().__init__()

    


    def new_task(self, task):
        pass

    def execute_task(self):
        pass

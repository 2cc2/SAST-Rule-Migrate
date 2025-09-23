from typing import override
from .base import BaseAgent


class MinAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__()
    

    @override
    def new_task(self, task):
        self.task = task
    
    def get_system_prompt(self):
        return super().get_system_prompt()


    @override
    def execute_task(self):
        return super().execute_task()
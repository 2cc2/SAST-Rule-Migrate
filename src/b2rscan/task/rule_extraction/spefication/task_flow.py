from dataclasses import dataclass

@dataclass
class UnderstandTask:
    task_name: str
    task_description: str
    task_input: str
    task_output: str
    task_steps: list


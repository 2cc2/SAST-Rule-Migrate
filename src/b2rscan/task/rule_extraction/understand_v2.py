from b2rscan.llm_wrapper import LLMWrapper


class SASTUnderstandAgent:
    """Understand Agent for SAST tools."""
    def __init__(self, sast_name, sast_code_path) -> None:
        self.sast_name = sast_name
        self.sast_code_path = sast_code_path


    def 
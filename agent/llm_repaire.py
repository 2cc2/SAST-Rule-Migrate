# llm_repairer.py

import openai
import time
import logging

openai.api_key = "YOUR_OPENAI_API_KEY"

class LLMRepairer:
    def __init__(self, model="gpt-4", max_retries=3):
        self.model = model
        self.max_retries = max_retries
        self.logger = logging.getLogger(__name__)

    def generate_prompt(self, original_rule: str, target_tool: str, error_message: str = "") -> str:
        prompt = f"""
You are a static analysis rule migration expert.

Your task is to fix or re-generate a rule definition from one static analysis tool to another.

---
Original Rule:
{original_rule}

Target Tool: {target_tool}

Error Message (if any):
{error_message}

---
Please return a revised rule in the format of the target tool that preserves the intent of the original rule, resolving any compatibility or semantic issues.
"""
        return prompt

    def call_llm(self, prompt: str) -> str:
        for attempt in range(self.max_retries):
            try:
                response = openai.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant for rule translation and repair."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                self.logger.warning(f"LLM call failed on attempt {attempt+1}: {e}")
                time.sleep(2)
        raise RuntimeError("LLM call failed after multiple attempts.")

    def repair_rule(self, original_rule: str, target_tool: str, error_message: str = "") -> str:
        prompt = self.generate_prompt(original_rule, target_tool, error_message)
        return self.call_llm(prompt)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    agent = LLMRepairer()

    # Example: A Bandit-style rule to migrate
    example_rule = """
    id: B001
    pattern: eval(user_input)
    message: Avoid using eval() with user input
    severity: HIGH
    """

    target = "Semgrep"
    error = "SyntaxError: unexpected key 'pattern' in Semgrep rule format"

    fixed_rule = agent.repair_rule(example_rule, target, error)
    print("\n[Fixed Rule Output]\n", fixed_rule)
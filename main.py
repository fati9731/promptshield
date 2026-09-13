import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

PROMPTS_FILE = BASE_DIR / "samples" / "prompts.txt"
REPORT_FILE = BASE_DIR / "reports" / "prompt_analysis_report.txt"

class SecurityRule:
    def __init__(self, name, pattern, score , severity , description):
        self.name = name
        self.pattern = pattern
        self.score = score
        self.severity = severity
        self.description = description

    def matches(self, prompt):
        return bool(re.search(self.pattern, prompt))
    

rules = [
    SecurityRule(
        "instruction_override",
        r"ignore\s+(all\s+|your\s+|the\s+)?previous\s+instructions?",
        40,
        severity="High",
        description="Attempts to override or ignore previous LLM instructions."
    ),

    SecurityRule(
        "system_prompt_extraction",
        r"(show|reveal|print|give|display)\s+(me\s+)?(your\s+|the\s+)?system\s+prompt",
        30,
        severity="Medium",
        description="Attempts to extract the hidden system prompt."
    ),

    SecurityRule(
        "developer_prompt_extraction",
        r"(show|reveal|print)\s+(me\s+)?(your\s+|the\s+)?developer\s+(prompt|instructions|message)",
        30,
        severity="Medium",
        description="Attempts to reveal developer-level instructions."
    )
]

class PromptAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self, prompt):
        self.score = 0
        self.detected_rules = []
        for rule in self.rules:
            if rule.matches(prompt):
                self.detected_rules.append(rule)
                self.score += rule.score

        self.score = min(self.score, 100)
        return self.score, self.detected_rules

    def get_risk_level(self):
        if self.score == 0:
            return "Safe"
        elif self.score <= 50:
            return "Low"
        elif self.score <= 80:
            return "Medium"
        else:
            return "High"



if __name__ == "__main__":
    analyzer = PromptAnalyzer(rules)

    try:
        with open(REPORT_FILE, "w") as report_file:
            report_file.write("Prompt Analysis Report\n")
            report_file.write("======================\n\n")

            with open(PROMPTS_FILE, "r") as file:
                for line in file:
                    client_prompt = line.strip().lower()

                    if not client_prompt:
                        continue

                    score, detected_rules = analyzer.analyze(client_prompt)
                    risk_level = analyzer.get_risk_level()

                    print(
                        f"Prompt: {client_prompt}\n"
                        f"Score: {score}\n"
                        f"Risk Level: {risk_level}\n"
                    )

                    report_file.write(
                        f"Prompt: {client_prompt}\n"
                        f"Score: {score}\n"
                        f"Risk Level: {risk_level}\n"
                    )

                    if detected_rules:
                        report_file.write("Detected rules:\n")

                        for rule in detected_rules:
                            report_file.write(
                                f"- {rule.name} (Score: {rule.score}, Severity: {rule.severity})\n"
                                f"  Description: {rule.description}\n"
                            )
                    else:
                        report_file.write("Detected rules: None\n")

                    report_file.write(
                        "\n----------------------------------------\n\n"
                    )

    except FileNotFoundError as error:
        print(f"File error: {error}")
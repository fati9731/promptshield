import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

PROMPTS_FILE = BASE_DIR / "samples" / "prompts.txt"
REPORT_FILE = BASE_DIR / "reports" / "prompt_analysis_report.txt"


prompt_injections = {
    "instruction_override": {
        "pattern": r"ignore\s+(all\s+|your\s+|the\s+)?previous\s+instructions?",
        "score": 40
    },

    "system_prompt_extraction": {
        "pattern": r"(show|reveal|print|give|display)\s+(me\s+)?(your\s+|the\s+)?system\s+prompt",
        "score": 30
    },

    "developer_prompt_extraction": {
        "pattern": r"(show|reveal|print)\s+(me\s+)?(your\s+|the\s+)?developer\s+(prompt|instructions|message)",
        "score": 30
    }
}

class PromptAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self, prompt):
        self.score = 0
        self.detected_injections = []

        for injection_name, injection_data in self.rules.items():
            pattern = injection_data["pattern"]
            injection_score = injection_data["score"]

            if re.search(pattern, prompt):
                self.detected_injections.append(injection_name)
                self.score += injection_score

        return self.score, self.detected_injections

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
    analyzer = PromptAnalyzer(prompt_injections)

    try:
        with open(REPORT_FILE, "w") as report_file:
            report_file.write("Prompt Analysis Report\n")
            report_file.write("======================\n\n")

            with open(PROMPTS_FILE, "r") as file:
                for line in file:
                    client_prompt = line.strip().lower()

                    if not client_prompt:
                        continue

                    score, detected_injections = analyzer.analyze(client_prompt)
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

                    if detected_injections:
                        report_file.write("Detected injections:\n")

                        for injection in detected_injections:
                            report_file.write(f"- {injection}\n")
                    else:
                        report_file.write("Detected injections: None\n")

                    report_file.write(
                        "\n----------------------------------------\n\n"
                    )

    except FileNotFoundError as error:
        print(f"File error: {error}")
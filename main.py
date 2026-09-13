from pathlib import Path
from rules import rules
from analyzer import PromptAnalyzer
from reporter import format_result


BASE_DIR = Path(__file__).resolve().parent

PROMPTS_FILE = BASE_DIR / "samples" / "prompts.txt"
REPORT_FILE = BASE_DIR / "reports" / "prompt_analysis_report.txt"


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

                    score, detected_rules = analyzer.analyze(
                        client_prompt
                    )

                    risk_level = analyzer.get_risk_level()

                    result = format_result(
                        client_prompt,
                        score,
                        risk_level,
                        detected_rules
                    )

                    print(result)
                    report_file.write(result)

    except FileNotFoundError as error:
        print(f"File error: {error}")
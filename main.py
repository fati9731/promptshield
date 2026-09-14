from pathlib import Path
from rules import rules
from analyzer import PromptAnalyzer
from reporter import format_result, format_summary

BASE_DIR = Path(__file__).resolve().parent

PROMPTS_FILE = BASE_DIR / "samples" / "prompts.txt"
REPORT_FILE = BASE_DIR / "reports" / "prompt_analysis_report.txt"

def create_stats():
    return {
        "total": 0,
        "Safe": 0,
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "threats": 0
    }

def record(stats, risk_level, detected_rules):
    stats["total"] += 1
    stats[risk_level] += 1
    stats["threats"] += len(detected_rules)

def analyze_single_prompt(analyzer, session_stats):
    prompt = input("Enter the prompt to analyze: ").strip().lower()

    if not prompt:
        print("Prompt cannot be empty.")
        return

    score, detected_rules = analyzer.analyze(prompt)
    risk_level = analyzer.get_risk_level()

    record(session_stats, risk_level, detected_rules)

    print(format_result(prompt, score, risk_level, detected_rules))
    print(format_summary(session_stats, "Session Summary"))

def analyze_prompts_from_file(analyzer, file_path, report_path, session_stats):
    run_stats = create_stats()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            with open(report_path, "w", encoding="utf-8") as report_file:

                report_file.write("Prompt Analysis Report\n")
                report_file.write("======================\n\n")

                for line in file:
                    client_prompt = line.strip().lower()

                    if not client_prompt:
                        continue

                    score, detected_rules = analyzer.analyze(client_prompt)
                    risk_level = analyzer.get_risk_level()

                    record(run_stats, risk_level, detected_rules)
                    record(session_stats, risk_level, detected_rules)

                    result = format_result(
                        client_prompt,
                        score,
                        risk_level,
                        detected_rules
                    )

                    print(result)
                    report_file.write(result)

                report_file.write(format_summary(run_stats))

        print(format_summary(session_stats, "Session Summary"))
        print(f"Analysis report saved to {report_path}")

    except FileNotFoundError as error:
        print(f"File error: {error}")

def main():
    analyzer = PromptAnalyzer(rules)
    session_stats = create_stats()

    while True:
        print("\nPromptShield")
        print("========================")
        print("1. Analyze a single prompt")
        print("2. Analyze prompts from file")
        print("3. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":
            analyze_single_prompt(analyzer, session_stats)

        elif choice == "2":
            analyze_prompts_from_file(
                analyzer, PROMPTS_FILE, REPORT_FILE, session_stats
            )

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()

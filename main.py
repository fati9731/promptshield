from pathlib import Path

from detector import HybridDetector
from reporter import format_analysis, format_summary

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

def record(stats, result):
    stats["total"] += 1
    stats[result["risk"]] += 1

    if result["hybrid_decision"]:
        stats["threats"] += 1

def analyze_single_prompt(detector, session_stats):
    prompt = input("Enter the prompt to analyze: ").strip()

    if not prompt:
        print("Prompt cannot be empty.")
        return

    result = detector.analyze(prompt)
    record(session_stats, result)

    print()
    print(format_analysis(result))
    print(format_summary(session_stats, "Session Summary"))

def analyze_prompts_from_file(detector, file_path, report_path, session_stats):
    run_stats = create_stats()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            with open(report_path, "w", encoding="utf-8") as report_file:

                report_file.write("Prompt Analysis Report\n")
                report_file.write("======================\n\n")

                for line in file:
                    client_prompt = line.strip()

                    if not client_prompt:
                        continue

                    result = detector.analyze(client_prompt)

                    record(run_stats, result)
                    record(session_stats, result)

                    rendered = format_analysis(result)

                    print(rendered)
                    report_file.write(rendered)

                report_file.write(format_summary(run_stats))

        print(format_summary(session_stats, "Session Summary"))
        print(f"Analysis report saved to {report_path}")

    except FileNotFoundError as error:
        print(f"File error: {error}")

def main():
    detector = HybridDetector()
    session_stats = create_stats()

    print("\nPromptShield")
    print("========================")
    print("Loading the classifier ...")

    if detector.model_available:
        print(
            "Rule engine + TF-IDF classifier "
            f"(threshold {detector.threshold:.2f})"
        )
    else:
        # The rules alone are what v1 shipped; say so rather than reporting
        # a hybrid decision that is really one detector.
        print(f"Rules only - {detector.unavailable_reason}")

    while True:
        print("\nPromptShield")
        print("========================")
        print("1. Analyze a single prompt")
        print("2. Analyze prompts from file")
        print("3. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":
            analyze_single_prompt(detector, session_stats)

        elif choice == "2":
            analyze_prompts_from_file(
                detector, PROMPTS_FILE, REPORT_FILE, session_stats
            )

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()

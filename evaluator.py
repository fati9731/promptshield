from pathlib import Path
from analyzer import PromptAnalyzer
from rules import rules


BASE_DIR = Path(__file__).resolve().parent
EVALUATION_FILE = BASE_DIR / "samples" / "evaluation_prompts.txt"
HARD_EVALUATION_FILE = BASE_DIR / "samples" / "hard_evaluation_prompts.txt"
ADVERSARIAL_DEV_FILE = (BASE_DIR / "samples" / "adversarial_dev_prompts.txt")
FINAL_HOLDOUT_FILE = (BASE_DIR / "samples" / "final_holdout_prompts.txt")

def calculate_metrics(file_path):
    analyzer = PromptAnalyzer(rules)

    metrics = {
        "TP": 0,
        "FP": 0,
        "TN": 0,
        "FN": 0
    }
    false_positives = []
    false_negatives = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            expected_label, prompt = line.split("|", 1)

            expected_label = expected_label.strip().lower()
            prompt = prompt.strip().lower()

            _, detected_rules = analyzer.analyze(prompt)

            if detected_rules:
                predicted_label = "malicious"
            else:
                predicted_label = "safe"

            if expected_label == "malicious" and predicted_label == "malicious":
                metrics["TP"] += 1

            elif expected_label == "safe" and predicted_label == "malicious":
                metrics["FP"] += 1
                false_positives.append({
                    "prompt": prompt,
                    "detected_rules": detected_rules
                })

            elif expected_label == "safe" and predicted_label == "safe":
                metrics["TN"] += 1

            elif expected_label == "malicious" and predicted_label == "safe":
                metrics["FN"] += 1
                false_negatives.append({
                    "prompt": prompt
                })

    total = (
        metrics["TP"]
        + metrics["FP"]
        + metrics["TN"]
        + metrics["FN"]
    )

    accuracy = (
        (metrics["TP"] + metrics["TN"]) / total
        if total > 0 else 0
    )

    precision = (
        metrics["TP"] / (metrics["TP"] + metrics["FP"])
        if (metrics["TP"] + metrics["FP"]) > 0 else 0
    )

    recall = (
        metrics["TP"] / (metrics["TP"] + metrics["FN"])
        if (metrics["TP"] + metrics["FN"]) > 0 else 0
    )
    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0
    )

    return metrics, accuracy, precision, recall, f1_score, false_positives, false_negatives

def print_evaluation(
    title,
    metrics,
    accuracy,
    precision,
    recall,
    f1_score,
    false_positives,
    false_negatives
):
    print(f"\n{title}")
    print("=" * len(title))

    print(f"True Positives:  {metrics['TP']}")
    print(f"False Positives: {metrics['FP']}")
    print(f"True Negatives:  {metrics['TN']}")
    print(f"False Negatives: {metrics['FN']}")

    print(f"\nAccuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1 Score:  {f1_score:.2%}")

    print("\nFalse Positives")
    print("------------------------")

    if false_positives:
        for item in false_positives:
            print(f"\nPrompt: {item['prompt']}")
            print("Detected rules:")

            for rule in item["detected_rules"]:
                print(f"- {rule.name}")
    else:
        print("None")

    print("\nFalse Negatives")
    print("------------------------")

    if false_negatives:
        for item in false_negatives:
            print(f"\nPrompt: {item['prompt']}")
    else:
        print("None")

if __name__ == "__main__":

    normal_results = calculate_metrics(EVALUATION_FILE)

    print_evaluation(
        "Standard Evaluation",
        *normal_results
    )

    hard_results = calculate_metrics(HARD_EVALUATION_FILE)

    print_evaluation(
        "Hard Evaluation",
        *hard_results
    )
    
    dev_results = calculate_metrics(ADVERSARIAL_DEV_FILE)

    print_evaluation(
        "Adversarial Dev Evaluation",
        *dev_results
    )

    final_holdout_results = calculate_metrics(FINAL_HOLDOUT_FILE)

    print_evaluation(
        "Final Holdout Evaluation",
        *final_holdout_results
    )

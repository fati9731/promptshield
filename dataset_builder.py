from pathlib import Path
import csv


BASE_DIR = Path(__file__).resolve().parent

SOURCE_FILES = [
    BASE_DIR / "samples" / "evaluation_prompts.txt",
    BASE_DIR / "samples" / "hard_evaluation_prompts.txt",
    BASE_DIR / "samples" / "adversarial_dev_prompts.txt",
    BASE_DIR / "samples" / "final_holdout_prompts.txt",
    BASE_DIR / "samples" / "v1_1_final_holdout_prompts.txt",
]

def load_labeled_file(path):
    samples = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            if "|" not in line:
                raise ValueError(
                    f"{path.name}:{line_number} - Missing '|' separator"
                )

            label_text, prompt = line.split("|", 1)

            label_text = label_text.strip().lower()
            prompt = prompt.strip()

            if label_text not in {"safe", "malicious"}:
                raise ValueError(
                    f"{path.name}:{line_number} - "
                    f"Invalid label: {label_text}"
                )

            if not prompt:
                raise ValueError(
                    f"{path.name}:{line_number} - Empty prompt"
                )

            label = 1 if label_text == "malicious" else 0

            samples.append({
                "text": prompt,
                "label": label,
                "source": path.name,
            })

    return samples

def normalize_for_duplicate_check(text):
    return " ".join(
        text.lower().split()
    )

def analyze_dataset(samples):
    unique_samples = {}
    duplicates = []
    conflicts = []

    for sample in samples:
        key = normalize_for_duplicate_check(
            sample["text"]
        )

        if key not in unique_samples:
            unique_samples[key] = sample
            continue

        existing = unique_samples[key]

        if existing["label"] == sample["label"]:
            duplicates.append({
                "text": sample["text"],
                "first_source": existing["source"],
                "duplicate_source": sample["source"],
            })
        else:
            conflicts.append({
                "text": sample["text"],
                "first_label": existing["label"],
                "first_source": existing["source"],
                "second_label": sample["label"],
                "second_source": sample["source"],
            })

    return (
        list(unique_samples.values()),
        duplicates,
        conflicts,
    )

if __name__ == "__main__":
    all_samples = []

    for source_file in SOURCE_FILES:
        samples = load_labeled_file(source_file)
        all_samples.extend(samples)

    unique_samples, duplicates, conflicts = analyze_dataset(
        all_samples
    )

    malicious_count = sum(
        sample["label"] == 1
        for sample in unique_samples
    )

    safe_count = sum(
        sample["label"] == 0
        for sample in unique_samples
    )

    print("Raw samples:", len(all_samples))
    print("Unique samples:", len(unique_samples))
    print("Duplicates:", len(duplicates))
    print("Conflicting labels:", len(conflicts))
    print()
    print("Malicious:", malicious_count)
    print("Safe:", safe_count)

    if duplicates:
        print("\nDuplicates")
        print("-" * 50)

        for duplicate in duplicates:
            print(duplicate)

    if conflicts:
        print("\nCONFLICTS")
        print("-" * 50)

        for conflict in conflicts:
            print(conflict)

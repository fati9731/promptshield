from pathlib import Path
import csv
import random

BASE_DIR = Path(__file__).resolve().parent

SOURCE_FILES = [
    BASE_DIR / "samples" / "evaluation_prompts.txt",
    BASE_DIR / "samples" / "hard_evaluation_prompts.txt",
    BASE_DIR / "samples" / "adversarial_dev_prompts.txt",
    BASE_DIR / "samples" / "final_holdout_prompts.txt",
    BASE_DIR / "samples" / "v1_1_final_holdout_prompts.txt",
]

PROCESSED_DIR = BASE_DIR / "dataset" / "processed"
TRAIN_FILE = PROCESSED_DIR / "train.csv"
VALIDATION_FILE = PROCESSED_DIR / "validation.csv"


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

def split_dataset(samples, validation_ratio=0.2, seed=42):
    malicious = [
        sample for sample in samples
        if sample["label"] == 1
    ]

    safe = [
        sample for sample in samples
        if sample["label"] == 0
    ]

    rng = random.Random(seed)

    rng.shuffle(malicious)
    rng.shuffle(safe)

    malicious_val_size = round(
        len(malicious) * validation_ratio
    )

    safe_val_size = round(
        len(safe) * validation_ratio
    )

    validation_samples = (
        malicious[:malicious_val_size]
        + safe[:safe_val_size]
    )

    train_samples = (
        malicious[malicious_val_size:]
        + safe[safe_val_size:]
    )

    rng.shuffle(train_samples)
    rng.shuffle(validation_samples)

    return train_samples, validation_samples

def write_csv(path, samples):
    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "text",
                "label",
                "source",
            ]
        )

        writer.writeheader()
        writer.writerows(samples)


def load_csv(path):
    """Read a written split back into parallel texts and labels."""
    texts = []
    labels = []

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))

    return texts, labels


def ensure_built():
    """Build the split unless it is already on disk.

    dataset/processed is git-ignored because the split regenerates
    deterministically, so a fresh checkout has nothing to read. Anything
    consuming the CSVs calls this first rather than crashing on a
    missing file.
    """
    if TRAIN_FILE.exists() and VALIDATION_FILE.exists():
        return False

    print("dataset/processed is empty - building it from samples/ ...\n")
    build()
    return True


def print_split_stats(name, samples):
    malicious_count = sum(
        sample["label"] == 1
        for sample in samples
    )

    safe_count = sum(
        sample["label"] == 0
        for sample in samples
    )

    print(name)
    print("Total:", len(samples))
    print("Malicious:", malicious_count)
    print("Safe:", safe_count)
    print("-" * 50)


def build():
    """Read samples/, de-duplicate, split, and write the CSVs.

    Importable so anything that needs the split can produce it instead
    of failing on a checkout where dataset/processed is empty -- the
    CSVs are git-ignored because they regenerate deterministically.
    """
    all_samples = []

    for source_file in SOURCE_FILES:
        all_samples.extend(load_labeled_file(source_file))

    unique_samples, duplicates, conflicts = analyze_dataset(all_samples)
    train_samples, validation_samples = split_dataset(unique_samples)

    write_csv(TRAIN_FILE, train_samples)
    write_csv(VALIDATION_FILE, validation_samples)

    return {
        "all_samples": all_samples,
        "unique_samples": unique_samples,
        "duplicates": duplicates,
        "conflicts": conflicts,
        "train_samples": train_samples,
        "validation_samples": validation_samples,
    }


if __name__ == "__main__":
    result = build()

    all_samples = result["all_samples"]
    unique_samples = result["unique_samples"]
    duplicates = result["duplicates"]
    conflicts = result["conflicts"]
    train_samples = result["train_samples"]
    validation_samples = result["validation_samples"]

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
    
    print()
    print_split_stats("TRAIN", train_samples)
    print_split_stats(
        "VALIDATION",
        validation_samples
    )

    print("Saved:")
    print(TRAIN_FILE)
    print(VALIDATION_FILE)

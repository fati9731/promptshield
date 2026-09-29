from pathlib import Path
import csv
import hashlib

from analyzer import PromptAnalyzer
from rules import rules

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


BASE_DIR = Path(__file__).resolve().parent

TRAIN_FILE = (
    BASE_DIR
    / "dataset"
    / "processed"
    / "train.csv"
)

VALIDATION_FILE = (
    BASE_DIR
    / "dataset"
    / "processed"
    / "validation.csv"
)

FINAL_FILE = (
    BASE_DIR
    / "samples"
    / "v3_final_holdout_prompts.txt"
)

EXPECTED_SHA256 = (
    "bc4a9db64e6229fde3441fc595576957"
    "cdc26edad56ab981915c5c3df10b6ecc"
)

ML_THRESHOLD = 0.50


def load_development_csv(path):
    samples = []

    with path.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            samples.append({
                "text": row["text"],
                "label": int(row["label"]),
            })

    return samples


def load_final_holdout(path):
    samples = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            if "|" not in line:
                raise ValueError(
                    f"Line {line_number}: "
                    f"missing '|' separator"
                )

            label_text, prompt = line.split(
                "|",
                1
            )

            label_text = (
                label_text
                .strip()
                .lower()
            )

            prompt = prompt.strip()

            if label_text not in {
                "safe",
                "malicious",
            }:
                raise ValueError(
                    f"Line {line_number}: "
                    f"invalid label "
                    f"{label_text}"
                )

            if not prompt:
                raise ValueError(
                    f"Line {line_number}: "
                    f"empty prompt"
                )

            label = (
                1
                if label_text == "malicious"
                else 0
            )

            samples.append({
                "text": prompt,
                "label": label,
            })

    return samples


def normalize_for_duplicate_check(text):
    return " ".join(
        text.lower().split()
    )


def calculate_metrics(
    true_labels,
    predictions
):
    tn, fp, fn, tp = confusion_matrix(
        true_labels,
        predictions,
        labels=[0, 1],
    ).ravel()

    return {
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),

        "accuracy": accuracy_score(
            true_labels,
            predictions
        ),

        "precision": precision_score(
            true_labels,
            predictions,
            zero_division=0,
        ),

        "recall": recall_score(
            true_labels,
            predictions,
            zero_division=0,
        ),

        "f1": f1_score(
            true_labels,
            predictions,
            zero_division=0,
        ),
    }


def print_metrics(
    name,
    metrics
):
    print()
    print(name)
    print("=" * len(name))

    print(
        f"True Positives:  "
        f"{metrics['tp']}"
    )

    print(
        f"False Positives: "
        f"{metrics['fp']}"
    )

    print(
        f"True Negatives:  "
        f"{metrics['tn']}"
    )

    print(
        f"False Negatives: "
        f"{metrics['fn']}"
    )

    print()

    print(
        f"Accuracy:  "
        f"{metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision: "
        f"{metrics['precision'] * 100:.2f}%"
    )

    print(
        f"Recall:    "
        f"{metrics['recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score:  "
        f"{metrics['f1'] * 100:.2f}%"
    )


# ==================================================
# 1. LOAD DATA
# ==================================================

development_samples = (
    load_development_csv(TRAIN_FILE)
    + load_development_csv(VALIDATION_FILE)
)

final_samples = load_final_holdout(
    FINAL_FILE
)


print(
    "PromptShield v3 Final Evaluation"
)

print("=" * 60)


# ==================================================
# 2. VERIFY FILE HASH
# ==================================================

actual_sha256 = hashlib.sha256(
    FINAL_FILE.read_bytes()
).hexdigest()

print()
print(
    "Final holdout SHA-256:",
    actual_sha256
)

if actual_sha256 != EXPECTED_SHA256:
    raise ValueError(
        "Final holdout SHA-256 does not "
        "match the frozen manifest."
    )


# ==================================================
# 3. DATASET INTEGRITY
# ==================================================

development_count = len(
    development_samples
)

final_count = len(
    final_samples
)

safe_count = sum(
    sample["label"] == 0
    for sample in final_samples
)

malicious_count = sum(
    sample["label"] == 1
    for sample in final_samples
)


final_keys = [
    normalize_for_duplicate_check(
        sample["text"]
    )
    for sample in final_samples
]

internal_duplicates = (
    len(final_keys)
    - len(set(final_keys))
)


development_keys = {
    normalize_for_duplicate_check(
        sample["text"]
    )
    for sample in development_samples
}

overlap = (
    development_keys
    & set(final_keys)
)


print()
print(
    "Development samples:",
    development_count
)

print(
    "Final holdout samples:",
    final_count
)

print(
    "Safe:",
    safe_count
)

print(
    "Malicious:",
    malicious_count
)

print(
    "Internal duplicates:",
    internal_duplicates
)

print(
    "Development/final exact overlap:",
    len(overlap)
)


if development_count != 675:
    raise ValueError(
        "Expected exactly 675 "
        "development samples."
    )

if final_count != 300:
    raise ValueError(
        "Expected exactly 300 "
        "final samples."
    )

if safe_count != 150:
    raise ValueError(
        "Expected exactly 150 "
        "safe final samples."
    )

if malicious_count != 150:
    raise ValueError(
        "Expected exactly 150 "
        "malicious final samples."
    )

if internal_duplicates != 0:
    raise ValueError(
        "Final holdout contains "
        "duplicate prompts."
    )

if overlap:
    raise ValueError(
        "Final holdout overlaps "
        "with development data."
    )


print()
print(
    "Integrity checks: PASSED"
)


# ==================================================
# 4. PREPARE DEVELOPMENT DATA
# ==================================================

development_texts = [
    sample["text"]
    for sample in development_samples
]

development_labels = [
    sample["label"]
    for sample in development_samples
]

final_texts = [
    sample["text"]
    for sample in final_samples
]

true_labels = [
    sample["label"]
    for sample in final_samples
]


# ==================================================
# 5. TRAIN FROZEN ML CANDIDATE
# ==================================================

vectorizer = TfidfVectorizer()

X_development = (
    vectorizer.fit_transform(
        development_texts
    )
)

X_final = vectorizer.transform(
    final_texts
)


model = LogisticRegression(
    max_iter=1000,
    random_state=42,
)

model.fit(
    X_development,
    development_labels,
)


# ==================================================
# 6. ML PREDICTIONS
# ==================================================

ml_probabilities = (
    model.predict_proba(
        X_final
    )[:, 1]
)

ml_predictions = [
    1
    if probability >= ML_THRESHOLD
    else 0

    for probability
    in ml_probabilities
]


# ==================================================
# 7. RULE ENGINE PREDICTIONS
# ==================================================

analyzer = PromptAnalyzer(
    rules
)

rule_predictions = []


for text in final_texts:

    _, detected_rules = (
        analyzer.analyze(text)
    )

    rule_prediction = (
        1
        if detected_rules
        else 0
    )

    rule_predictions.append(
        rule_prediction
    )


# ==================================================
# 8. HYBRID OR
# ==================================================

hybrid_predictions = [
    1
    if (
        rule_prediction == 1
        or ml_prediction == 1
    )
    else 0

    for (
        rule_prediction,
        ml_prediction
    )
    in zip(
        rule_predictions,
        ml_predictions
    )
]


# ==================================================
# 9. METRICS
# ==================================================

rule_metrics = calculate_metrics(
    true_labels,
    rule_predictions
)

ml_metrics = calculate_metrics(
    true_labels,
    ml_predictions
)

hybrid_metrics = calculate_metrics(
    true_labels,
    hybrid_predictions
)


print()
print("=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print_metrics(
    "RULE ENGINE",
    rule_metrics
)

print_metrics(
    "ML",
    ml_metrics
)

print_metrics(
    "HYBRID OR",
    hybrid_metrics
)


# ==================================================
# 10. COMPLEMENTARITY SUMMARY
# ==================================================

rule_rescues_ml = sum(
    true == 1
    and ml == 0
    and rule == 1

    for true, ml, rule
    in zip(
        true_labels,
        ml_predictions,
        rule_predictions,
    )
)

rule_added_fp = sum(
    true == 0
    and ml == 0
    and rule == 1

    for true, ml, rule
    in zip(
        true_labels,
        ml_predictions,
        rule_predictions,
    )
)


print()
print("HYBRID EFFECT")
print("=" * 60)

print(
    "Rule rescues ML attacks:",
    rule_rescues_ml
)

print(
    "Rule adds FP over ML:",
    rule_added_fp
)

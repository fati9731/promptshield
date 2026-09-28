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


from dataset_builder import (
    BASE_DIR,
    TRAIN_FILE,
    VALIDATION_FILE,
    ensure_built,
)

FINAL_FILE = (
    BASE_DIR
    / "samples"
    / "v2_final_holdout_prompts.txt"
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

    accuracy = accuracy_score(
        true_labels,
        predictions
    )

    precision = precision_score(
        true_labels,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        true_labels,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        true_labels,
        predictions,
        zero_division=0,
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
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


# --------------------------------------------------
# 1. Load frozen development dataset
# --------------------------------------------------

ensure_built()

development_samples = (
    load_development_csv(TRAIN_FILE)
    + load_development_csv(VALIDATION_FILE)
)

final_samples = load_final_holdout(
    FINAL_FILE
)


print("PromptShield v2 Final Evaluation")
print("=" * 60)

print(
    "Development samples:",
    len(development_samples)
)

print(
    "Final holdout samples:",
    len(final_samples)
)


# --------------------------------------------------
# 2. Check final dataset hash
# --------------------------------------------------

sha256 = hashlib.sha256(
    FINAL_FILE.read_bytes()
).hexdigest()

print()
print(
    "Final holdout SHA-256:",
    sha256
)


# --------------------------------------------------
# 3. Check exact train/test overlap
# --------------------------------------------------

development_keys = {
    normalize_for_duplicate_check(
        sample["text"]
    )
    for sample in development_samples
}

final_keys = {
    normalize_for_duplicate_check(
        sample["text"]
    )
    for sample in final_samples
}

overlap = (
    development_keys
    & final_keys
)

print()
print(
    "Exact development/final overlap:",
    len(overlap)
)

if overlap:
    raise ValueError(
        "Final holdout overlaps "
        "with development data."
    )


# --------------------------------------------------
# 4. Train ML on ALL development data
# --------------------------------------------------

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


# --------------------------------------------------
# 5. ML predictions
# --------------------------------------------------

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


# --------------------------------------------------
# 6. Rule Engine predictions
# --------------------------------------------------

analyzer = PromptAnalyzer(rules)

rule_predictions = []
rule_details = []


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

    rule_details.append([
        rule.name
        for rule in detected_rules
    ])


# --------------------------------------------------
# 7. Hybrid OR
# --------------------------------------------------

hybrid_predictions = [
    1
    if rule_prediction == 1
    or ml_prediction == 1
    else 0

    for rule_prediction, ml_prediction
    in zip(
        rule_predictions,
        ml_predictions
    )
]


# --------------------------------------------------
# 8. Final metrics
# --------------------------------------------------

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

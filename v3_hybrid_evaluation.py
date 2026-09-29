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
    TRAIN_FILE,
    VALIDATION_FILE,
    ensure_built,
    load_rows,
)


ML_THRESHOLD = 0.50


def calculate_metrics(true_labels, predictions):
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


def print_metrics(name, metrics):
    print()
    print(name)
    print("=" * len(name))

    print(f"TP: {metrics['tp']}")
    print(f"FP: {metrics['fp']}")
    print(f"TN: {metrics['tn']}")
    print(f"FN: {metrics['fn']}")

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
        f"F1:        "
        f"{metrics['f1'] * 100:.2f}%"
    )


ensure_built()

# The random split is irrelevant here; the source file is what gets held
# out, so both halves are recombined first.
all_samples = (
    load_rows(TRAIN_FILE)
    + load_rows(VALIDATION_FILE)
)

sources = sorted(
    set(
        sample["source"]
        for sample in all_samples
    )
)

analyzer = PromptAnalyzer(rules)

records = []


for held_out_source in sources:

    train_samples = [
        sample
        for sample in all_samples
        if sample["source"] != held_out_source
    ]

    validation_samples = [
        sample
        for sample in all_samples
        if sample["source"] == held_out_source
    ]

    train_texts = [
        sample["text"]
        for sample in train_samples
    ]

    train_labels = [
        sample["label"]
        for sample in train_samples
    ]

    validation_texts = [
        sample["text"]
        for sample in validation_samples
    ]

    vectorizer = TfidfVectorizer()

    X_train = vectorizer.fit_transform(
        train_texts
    )

    X_validation = vectorizer.transform(
        validation_texts
    )

    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
    )

    model.fit(
        X_train,
        train_labels,
    )

    probabilities = model.predict_proba(
        X_validation
    )[:, 1]

    ml_predictions = [
        1 if probability >= ML_THRESHOLD else 0
        for probability in probabilities
    ]

    for sample, probability, ml_prediction in zip(
        validation_samples,
        probabilities,
        ml_predictions,
    ):
        _, detected_rules = analyzer.analyze(
            sample["text"].lower()
        )

        rule_prediction = (
            1 if detected_rules else 0
        )

        hybrid_prediction = (
            1
            if rule_prediction == 1
            or ml_prediction == 1
            else 0
        )

        records.append({
            "text": sample["text"],
            "label": sample["label"],
            "source": sample["source"],

            "rule_prediction": rule_prediction,

            "ml_prediction": ml_prediction,
            "ml_probability": probability,

            "hybrid_prediction": hybrid_prediction,

            "detected_rules": [
                rule.name
                for rule in detected_rules
            ],
        })


print(
    "Total out-of-fold records:",
    len(records)
)

true_labels = [
    record["label"]
    for record in records
]

rule_predictions = [
    record["rule_prediction"]
    for record in records
]

ml_predictions = [
    record["ml_prediction"]
    for record in records
]

hybrid_predictions = [
    record["hybrid_prediction"]
    for record in records
]


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

both_correct = 0
rule_only_correct = 0
ml_only_correct = 0
both_wrong = 0


for record in records:
    expected = record["label"]

    rule_correct = (
        record["rule_prediction"] == expected
    )

    ml_correct = (
        record["ml_prediction"] == expected
    )

    if rule_correct and ml_correct:
        both_correct += 1

    elif rule_correct and not ml_correct:
        rule_only_correct += 1

    elif ml_correct and not rule_correct:
        ml_only_correct += 1

    else:
        both_wrong += 1


print()
print("COMPLEMENTARITY")
print("=" * 50)

print(
    "Both correct:",
    both_correct
)

print(
    "Rule correct, ML wrong:",
    rule_only_correct
)

print(
    "ML correct, Rule wrong:",
    ml_only_correct
)

print(
    "Both wrong:",
    both_wrong
)

rule_rescues_ml = 0
ml_rescues_rule = 0

rule_adds_false_positive = 0
ml_adds_false_positive = 0


for record in records:
    label = record["label"]

    rule_prediction = record[
        "rule_prediction"
    ]

    ml_prediction = record[
        "ml_prediction"
    ]

    if (
        label == 1
        and ml_prediction == 0
        and rule_prediction == 1
    ):
        rule_rescues_ml += 1

    if (
        label == 1
        and rule_prediction == 0
        and ml_prediction == 1
    ):
        ml_rescues_rule += 1

    if (
        label == 0
        and ml_prediction == 0
        and rule_prediction == 1
    ):
        rule_adds_false_positive += 1

    if (
        label == 0
        and rule_prediction == 0
        and ml_prediction == 1
    ):
        ml_adds_false_positive += 1


print()
print("HYBRID EFFECT")
print("=" * 50)

print(
    "Rule rescues ML attacks:",
    rule_rescues_ml
)

print(
    "ML rescues Rule attacks:",
    ml_rescues_rule
)

print(
    "Rule adds FP over ML:",
    rule_adds_false_positive
)

print(
    "ML adds FP over Rule:",
    ml_adds_false_positive
)

print()
print("BOTH WRONG")
print("=" * 50)

for record in records:
    expected = record["label"]

    rule_wrong = (
        record["rule_prediction"] != expected
    )

    ml_wrong = (
        record["ml_prediction"] != expected
    )

    if rule_wrong and ml_wrong:
        print("Source:", record["source"])
        print("Expected:", expected)
        print(
            "ML probability:",
            f"{record['ml_probability']:.3f}"
        )
        print(
            "Rule prediction:",
            record["rule_prediction"]
        )
        print(
            "ML prediction:",
            record["ml_prediction"]
        )
        print("Prompt:")
        print(record["text"])
        print()

print()
print("HYBRID FALSE POSITIVES")
print("=" * 50)

for record in records:
    if (
        record["label"] == 0
        and record["hybrid_prediction"] == 1
    ):
        print(
            f"{record['ml_probability']:.3f} | "
            f"{record['text']}"
        )

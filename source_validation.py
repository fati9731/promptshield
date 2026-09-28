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


ensure_built()

# Both halves are recombined: the random split is irrelevant here, the
# source file is what gets held out.
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


print("Sources:")
for source in sources:
    count = sum(
        sample["source"] == source
        for sample in all_samples
    )

    print(f"{source}: {count}")

def evaluate_source(all_samples, held_out_source):
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

    validation_labels = [
        sample["label"]
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

    predictions = model.predict(
        X_validation
    )

    probabilities = model.predict_proba(
        X_validation
    )[:, 1]

    prediction_records = []

    for text, true_label, probability in zip(
        validation_texts,
        validation_labels,
        probabilities,
    ):
        prediction_records.append({
            "text": text,
            "label": true_label,
            "probability": probability,
            "source": held_out_source,
        })

    tn, fp, fn, tp = confusion_matrix(
        validation_labels,
        predictions,
        labels=[0, 1],
    ).ravel()

    accuracy = accuracy_score(
        validation_labels,
        predictions
    )

    precision = precision_score(
        validation_labels,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        validation_labels,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        validation_labels,
        predictions,
        zero_division=0,
    )

    false_positives = []
    false_negatives = []

    for text, true_label, predicted_label, probability in zip(
        validation_texts,
        validation_labels,
        predictions,
        probabilities,
    ):
        if true_label == 0 and predicted_label == 1:
            false_positives.append({
                "text": text,
                "probability": probability,
            })

        elif true_label == 1 and predicted_label == 0:
            false_negatives.append({
                "text": text,
                "probability": probability,
            })

    return {
        "source": held_out_source,
        "train_size": len(train_samples),
        "validation_size": len(validation_samples),

        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,

        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,

        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "prediction_records": prediction_records,
    }

print()
print("Leave-One-Source-Out Evaluation")
print("=" * 70)

results = []
all_prediction_records = []

for source in sources:
    result = evaluate_source(
        all_samples,
        source
    )

    results.append(result)
    all_prediction_records.extend(
        result["prediction_records"]
    )

    print()
    print(f"Held-out source: {result['source']}")
    print(
        f"Train: {result['train_size']} | "
        f"Validation: {result['validation_size']}"
    )

    print(
        f"TP={result['tp']} "
        f"FP={result['fp']} "
        f"TN={result['tn']} "
        f"FN={result['fn']}"
    )

    print(
        f"Accuracy:  {result['accuracy'] * 100:.2f}%"
    )
    print(
        f"Precision: {result['precision'] * 100:.2f}%"
    )
    print(
        f"Recall:    {result['recall'] * 100:.2f}%"
    )
    print(
        f"F1:        {result['f1'] * 100:.2f}%"
    )

    if result["false_positives"]:
        print()
        print("False Positives")
        print("-" * 50)

        for item in result["false_positives"]:
            print(
                f"- {item['probability']:.3f} | "
                f"{item['text']}"
            )


    if result["false_negatives"]:
        print()
        print("False Negatives")
        print("-" * 50)

        for item in result["false_negatives"]:
            print(
                f"- {item['probability']:.3f} | "
                f"{item['text']}"
            )

average_accuracy = sum(
    result["accuracy"]
    for result in results
) / len(results)

average_precision = sum(
    result["precision"]
    for result in results
) / len(results)

average_recall = sum(
    result["recall"]
    for result in results
) / len(results)

average_f1 = sum(
    result["f1"]
    for result in results
) / len(results)


print()
print("=" * 70)
print("Average Across Sources")
print("=" * 70)

print(
    "Out-of-fold predictions:",
    len(all_prediction_records)
)

print(
    f"Accuracy:  {average_accuracy * 100:.2f}%"
)
print(
    f"Precision: {average_precision * 100:.2f}%"
)
print(
    f"Recall:    {average_recall * 100:.2f}%"
)
print(
    f"F1:        {average_f1 * 100:.2f}%"
)

def evaluate_threshold(records, threshold):
    true_labels = [
        record["label"]
        for record in records
    ]

    predicted_labels = [
        1 if record["probability"] >= threshold else 0
        for record in records
    ]

    tn, fp, fn, tp = confusion_matrix(
        true_labels,
        predicted_labels,
        labels=[0, 1],
    ).ravel()

    precision = precision_score(
        true_labels,
        predicted_labels,
        zero_division=0,
    )

    recall = recall_score(
        true_labels,
        predicted_labels,
        zero_division=0,
    )

    f1 = f1_score(
        true_labels,
        predicted_labels,
        zero_division=0,
    )

    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }

print()
print("=" * 70)
print("Threshold Sweep")
print("=" * 70)

thresholds = [
    0.30,
    0.35,
    0.40,
    0.45,
    0.50,
    0.55,
    0.60,
    0.65,
    0.70,
]

for threshold in thresholds:
    result = evaluate_threshold(
        all_prediction_records,
        threshold
    )

    print(
        f"{threshold:.2f} | "
        f"TP={result['tp']:3d} "
        f"FP={result['fp']:3d} "
        f"FN={result['fn']:3d} "
        f"TN={result['tn']:3d} | "
        f"P={result['precision'] * 100:6.2f}% "
        f"R={result['recall'] * 100:6.2f}% "
        f"F1={result['f1'] * 100:6.2f}%"
    )

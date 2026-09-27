import csv

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from dataset_builder import TRAIN_FILE, VALIDATION_FILE, ensure_built


def load_rows(path):
    """Rows with their source file kept, which the split loader drops."""
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
                "source": row["source"],
            })

    return samples


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
    }

print()
print("Leave-One-Source-Out Evaluation")
print("=" * 70)

results = []

for source in sources:
    result = evaluate_source(
        all_samples,
        source
    )

    results.append(result)

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

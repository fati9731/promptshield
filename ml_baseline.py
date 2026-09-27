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
    load_csv,
)


ensure_built()

train_texts, train_labels = load_csv(TRAIN_FILE)

validation_texts, validation_labels = load_csv(
    VALIDATION_FILE
)


# Step 1: Text -> TF-IDF vectors
vectorizer = TfidfVectorizer()

X_train = vectorizer.fit_transform(
    train_texts
)

X_validation = vectorizer.transform(
    validation_texts
)


# Step 2: Train classifier
model = LogisticRegression(
    max_iter=1000,
    random_state=42,
)

model.fit(
    X_train,
    train_labels,
)


# Step 3: Predict unseen validation samples
predictions = model.predict(
    X_validation
)


# Step 4: Evaluate
accuracy = accuracy_score(
    validation_labels,
    predictions
)

precision = precision_score(
    validation_labels,
    predictions
)

recall = recall_score(
    validation_labels,
    predictions
)

f1 = f1_score(
    validation_labels,
    predictions
)


tn, fp, fn, tp = confusion_matrix(
    validation_labels,
    predictions
).ravel()


print("ML Baseline Validation")
print("======================")
print(f"True Positives:  {tp}")
print(f"False Positives: {fp}")
print(f"True Negatives:  {tn}")
print(f"False Negatives: {fn}")

print()
print(f"Accuracy:  {accuracy * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall:    {recall * 100:.2f}%")
print(f"F1 Score:  {f1 * 100:.2f}%")

print()
print("False Positives")
print("-" * 60)

fp_count = 0

for text, true_label, predicted_label in zip(
    validation_texts,
    validation_labels,
    predictions
):
    if true_label == 0 and predicted_label == 1:
        fp_count += 1
        print(f"\nPrompt: {text}")

if fp_count == 0:
    print("None")


print()
print("False Negatives")
print("-" * 60)

fn_count = 0

for text, true_label, predicted_label in zip(
    validation_texts,
    validation_labels,
    predictions
):
    if true_label == 1 and predicted_label == 0:
        fn_count += 1
        print(f"\nPrompt: {text}")

if fn_count == 0:
    print("None")

feature_names = vectorizer.get_feature_names_out()
coefficients = model.coef_[0]

feature_weights = list(
    zip(feature_names, coefficients)
)

feature_weights.sort(
    key=lambda item: item[1],
    reverse=True
)


print()
print("Top Malicious Features")
print("-" * 60)

for feature, weight in feature_weights[:15]:
    print(f"{feature:<20} {weight:.4f}")


print()
print("Top Safe Features")
print("-" * 60)

for feature, weight in feature_weights[-15:]:
    print(f"{feature:<20} {weight:.4f}")
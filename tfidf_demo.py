from pathlib import Path
import csv

from sklearn.feature_extraction.text import TfidfVectorizer


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


def load_csv(path):
    texts = []
    labels = []

    with path.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))

    return texts, labels


train_texts, train_labels = load_csv(TRAIN_FILE)

validation_texts, validation_labels = load_csv(
    VALIDATION_FILE
)


vectorizer = TfidfVectorizer()

X_train = vectorizer.fit_transform(
    train_texts
)

X_validation = vectorizer.transform(
    validation_texts
)


print("Train samples:", len(train_texts))
print("Validation samples:", len(validation_texts))

print()
print("Train matrix shape:", X_train.shape)
print("Validation matrix shape:", X_validation.shape)

print()
print("Vocabulary size:", len(vectorizer.vocabulary_))

sample_index = 0

sample_text = train_texts[sample_index]
sample_vector = X_train[sample_index]

feature_names = vectorizer.get_feature_names_out()

print()
print("=" * 60)
print("Sample prompt:")
print(sample_text)

print()
print("Non-zero TF-IDF features:")
print("-" * 60)

for feature_index, value in zip(
    sample_vector.indices,
    sample_vector.data
):
    feature_name = feature_names[feature_index]

    print(
        f"{feature_name:<20} {value:.4f}"
    )

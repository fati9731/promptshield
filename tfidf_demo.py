import csv
from sklearn.feature_extraction.text import TfidfVectorizer
import dataset_builder
from dataset_builder import TRAIN_FILE, VALIDATION_FILE


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


# The CSVs are git-ignored, so a fresh checkout has none. They are
# deterministic, so rebuilding is cheaper than failing.
if not (TRAIN_FILE.exists() and VALIDATION_FILE.exists()):
    print("dataset/processed is empty - building it from samples/ ...\n")
    dataset_builder.build()


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

feature_names = vectorizer.get_feature_names_out()

def show_sample(texts, labels, matrix, wanted_label):
    for index, label in enumerate(labels):
        if label == wanted_label:
            sample_text = texts[index]
            sample_vector = matrix[index]

            print()
            print("=" * 60)

            if wanted_label == 1:
                print("MALICIOUS SAMPLE")
            else:
                print("SAFE SAMPLE")

            print("=" * 60)

            print("Prompt:")
            print(sample_text)

            print()
            print("TF-IDF features:")
            print("-" * 60)

            features = []

            for feature_index, value in zip(
                sample_vector.indices,
                sample_vector.data
            ):
                feature_name = feature_names[feature_index]

                features.append(
                    (feature_name, value)
                )

            features.sort(
                key=lambda item: item[1],
                reverse=True
            )

            for feature_name, value in features:
                print(
                    f"{feature_name:<20} {value:.4f}"
                )

            break


show_sample(
    train_texts,
    train_labels,
    X_train,
    wanted_label=1
)

show_sample(
    train_texts,
    train_labels,
    X_train,
    wanted_label=0
)

from sklearn.feature_extraction.text import TfidfVectorizer

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

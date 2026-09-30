"""The runtime detector: rule engine and classifier behind one call.

Evaluation scripts each fit their own model and throw it away. This is the
one place that assembles the decision the README reports, so `main.py` runs
the detector that was measured rather than half of it.
"""

from analyzer import PromptAnalyzer
from rules import rules

# Frozen after the v3 threshold sweep. Changing it invalidates every
# reported number until they are measured again.
ML_THRESHOLD = 0.50

# Probability bands for prompts the rules did not fire on. The rules carry
# their own severities; the classifier only returns a probability, so it
# needs a mapping to say anything about risk.
ML_HIGH = 0.80
ML_MEDIUM = 0.65

_RISK_ORDER = ["Safe", "Low", "Medium", "High"]


class ModelUnavailable(Exception):
    """scikit-learn or the corpus is missing, so only the rules can run."""


class HybridDetector:
    def __init__(self, threshold=ML_THRESHOLD):
        self.analyzer = PromptAnalyzer(rules)
        self.threshold = threshold
        self._vectorizer = None
        self._model = None
        self._unavailable = None

    # -- the classifier ------------------------------------------------

    def _fit(self):
        """Train on the whole development corpus, once per process.

        Nothing is persisted: the corpus is small, the fit takes a few
        hundredths of a second, and a stored model is one more thing that
        can silently fall out of step with samples/.
        """
        if self._model is not None or self._unavailable is not None:
            return

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression

            from dataset_builder import (
                TRAIN_FILE,
                VALIDATION_FILE,
                ensure_built,
                load_csv,
            )
        except ImportError as error:
            self._unavailable = f"scikit-learn is not installed ({error})"
            return

        try:
            ensure_built()

            train_texts, train_labels = load_csv(TRAIN_FILE)
            validation_texts, validation_labels = load_csv(VALIDATION_FILE)

            texts = train_texts + validation_texts
            labels = train_labels + validation_labels

            vectorizer = TfidfVectorizer()
            features = vectorizer.fit_transform(texts)

            model = LogisticRegression(max_iter=1000, random_state=42)
            model.fit(features, labels)
        except Exception as error:
            self._unavailable = f"the corpus could not be built ({error})"
            return

        self._vectorizer = vectorizer
        self._model = model

    @property
    def model_available(self):
        self._fit()
        return self._model is not None

    @property
    def unavailable_reason(self):
        self._fit()
        return self._unavailable

    def probability(self, prompt):
        """Probability the classifier assigns, or None if it cannot run."""
        self._fit()

        if self._model is None:
            return None

        features = self._vectorizer.transform([prompt])
        return float(self._model.predict_proba(features)[0][1])

    # -- the combined decision -----------------------------------------

    def _ml_risk(self, probability):
        if probability is None or probability < self.threshold:
            return "Safe"
        if probability >= ML_HIGH:
            return "High"
        if probability >= ML_MEDIUM:
            return "Medium"
        return "Low"

    def analyze(self, prompt):
        """Run both detectors and combine them.

        The combination is a union: either detector firing is enough. On the
        v3 holdout the rules added one detection and no false positives, so
        they cost nothing and are kept as a high-precision fallback.
        """
        score, detected_rules = self.analyzer.analyze(prompt)
        rule_risk = self.analyzer.get_risk_level()
        rule_decision = bool(detected_rules)

        probability = self.probability(prompt)
        ml_decision = (
            probability is not None and probability >= self.threshold
        )

        risk = max(
            rule_risk,
            self._ml_risk(probability),
            key=_RISK_ORDER.index,
        )

        return {
            "prompt": prompt,
            "score": score,
            "detected_rules": detected_rules,
            "rule_decision": rule_decision,
            "rule_risk": rule_risk,
            "ml_probability": probability,
            "ml_decision": ml_decision,
            "ml_available": probability is not None,
            "hybrid_decision": rule_decision or ml_decision,
            "risk": risk,
        }

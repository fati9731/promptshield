from normalizer import normalize_prompt

class PromptAnalyzer:
    def __init__(self, rules):
        self.rules = rules
        self.score = 0
        self.detected_rules = []

    def analyze(self, prompt):
        self.score = 0
        self.detected_rules = []

        original_prompt = prompt.lower().strip()
        normalized_prompt = normalize_prompt(prompt)

        for rule in self.rules:
            original_match = rule.matches(original_prompt)
            normalized_match = rule.matches(normalized_prompt)

            if original_match or normalized_match:
                self.detected_rules.append(rule)
                self.score += rule.score

        self.score = min(self.score, 100)

        return self.score, self.detected_rules

    def get_risk_level(self):
        if not self.detected_rules:
            return "Safe"

        severities = [
            rule.severity
            for rule in self.detected_rules
        ]

        if "High" in severities:
            return "High"

        elif "Medium" in severities:
            return "Medium"

        else:
            return "Low"

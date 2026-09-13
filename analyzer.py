class PromptAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self, prompt):
        self.score = 0
        self.detected_rules = []
        for rule in self.rules:
            if rule.matches(prompt):
                self.detected_rules.append(rule)
                self.score += rule.score

        self.score = min(self.score, 100)
        return self.score, self.detected_rules

    def get_risk_level(self):
        if self.score == 0:
            return "Safe"
        elif self.score <= 50:
            return "Low"
        elif self.score <= 80:
            return "Medium"
        else:
            return "High"
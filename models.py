import re


class SecurityRule:
    def __init__(self, name, patterns, score, severity, description, exclude=None):
        self.name = name
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.score = score
        self.severity = severity
        self.description = description
        self.exclude = [re.compile(p, re.IGNORECASE) for p in (exclude or [])]

    def matches(self, prompt):
        # A prompt that only talks *about* an attack is not an attack.
        for pattern in self.exclude:
            if pattern.search(prompt):
                return False

        for pattern in self.patterns:
            if pattern.search(prompt):
                return True

        return False

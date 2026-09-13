import re

class SecurityRule:
    def __init__(self, name, pattern, score , severity , description):
        self.name = name
        self.pattern = pattern
        self.score = score
        self.severity = severity
        self.description = description

    def matches(self, prompt):
        return bool(re.search(self.pattern, prompt))
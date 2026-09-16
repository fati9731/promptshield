import re


class SecurityRule:
    def __init__(self,name,patterns,score,severity,description,exclude=None,context_patterns=None):
        self.name = name
        self.patterns = [
            re.compile(p, re.IGNORECASE)
            for p in patterns
        ]

        self.score = score
        self.severity = severity
        self.description = description

        self.exclude = [
            re.compile(p, re.IGNORECASE)
            for p in (exclude or [])
        ]

        self.context_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (context_patterns or [])
        ]

    def matches(self, prompt):
        segments = re.split(
            r"[.!?;]+|\b(?:then|after that|next)\b",
            prompt
        )

        previous_segment = ""

        for segment in segments:
            segment = segment.strip()

            if not segment:
                continue

            attack_detected = any(
                re.search(pattern, segment)
                for pattern in self.patterns
            )

            discussion_detected = any(
                re.search(pattern, segment)
                for pattern in self.exclude
            )

            if attack_detected and not discussion_detected:
                return True

            if previous_segment:
                context = f"{previous_segment} {segment}"

                context_attack = any(
                    re.search(pattern, context)
                    for pattern in self.context_patterns
                )

                if context_attack:
                    return True

            previous_segment = segment

        return False

import re


PHRASE_RULES = [
    (
        r"\b(set|put)\s+aside\s+"
        r"(every|all|any|the|your)?\s*"
        r"(instructions?|guidance|directions?|directives?)\s+"
        r"(you\s+)?(received|were\s+given)?\s*"
        r"(earlier|before|previously)?",
        "ignore previous instructions"
    ),

    (
        r"\b(do\s+not|don't)\s+obey\s+"
        r"(the\s+|your\s+)?"
        r"(previous|prior|earlier)\s+"
        r"(instructions?|directives?|rules?|guidance)",
        "ignore previous instructions"
    ),

    (
        r"\b(treat|consider)\s+"
        r"(all\s+|the\s+|your\s+)?"
        r"(prior|previous|earlier)\s+"
        r"(guidance|instructions?|directives?|rules?)\s+"
        r"as\s+(obsolete|invalid|void|cancelled|canceled)",
        "ignore previous instructions"
    ),

    (
        r"\b(instructions?|rules?|directives?)\s+"
        r"(you\s+)?(began|started)\s+with\s+"
        r"(are\s+|were\s+)?"
        r"(cancelled|canceled|void|invalid|obsolete)",
        "ignore previous instructions"
    ),

    (
        r"\b(ignore|discard|forget)\s+"
        r"(any\s+|all\s+|the\s+)?"
        r"(guidance|instructions?|rules?|directives?)\s+"
        r"(above|before)\s+"
        r"(this\s+)?(point|message)",
        "ignore previous instructions"
    ),
    (
        r"\b(copy|provide|show|reveal)\s+"
        r"(me\s+)?(the\s+)?"
        r"(secret|hidden|private)\s+"
        r"(prompt|instructions?|directives?)"
        r"(\s+that\s+.*)?",
        "reveal hidden instructions"
    ),
    (
        r"\b(recite|repeat|show|give|provide)\s+"
        r"(me\s+)?(the\s+)?"
        r"(words|message|prompt|instructions?)\s+"
        r"(used\s+to\s+)?"
        r"(initialize|initialise|set\s+up|configure)\s+"
        r"(your\s+)?(behavior|behaviour|you)?",
        "reveal system prompt"
    ),
        (
        r"\bwhat\s+"
        r"(private|hidden|secret|internal)\s+"
        r"(instructions?|directives?|rules?|guidance)\s+"
        r"were\s+you\s+given"
        r"(\s+before\s+.*)?",
        "reveal hidden instructions"
    ),
]


WORD_RULES = [
    (r"\bdisregard\b", "ignore"),
    (r"\babandon\b", "ignore"),
    (r"\bdiscard\b", "ignore"),

    (r"\bprior\b", "previous"),
    (r"\bearlier\b", "previous"),
    (r"\bpreceding\b", "previous"),

    (r"\bdirectives?\b", "instructions"),
    (r"\bdirections?\b", "instructions"),
    (r"\bguidance\b", "instructions"),
    (r"\bguidelines?\b", "instructions"),

    (r"\bguardrails?\b", "safety restrictions"),
    (r"\bconstraints?\b", "restrictions"),
    (r"\blimitations?\b", "restrictions"),
]


def normalize_prompt(prompt):
    normalized = prompt.lower().strip()
    normalized = re.sub(r"\s+", " ", normalized)

    # Specific phrases first
    for pattern, replacement in PHRASE_RULES:
        normalized = re.sub(pattern, replacement, normalized)

    # General vocabulary second
    for pattern, replacement in WORD_RULES:
        normalized = re.sub(pattern, replacement, normalized)

    return normalized

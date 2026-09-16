from models import SecurityRule

# Shared vocabulary. Attacks are paraphrases of each other far more often
# than they are exact strings, so each rule matches a verb from one list
# against a target from another instead of a fixed phrase.
REVEAL = (
    r"(?:show|reveal|print|display|give|tell|share|output|repeat|echo|"
    r"expose|disclose|dump|paste|send|leak|uncover|unveil|spell\s+out|"
    r"write\s+out|read\s+back)"
)
DISCARD = (
    r"(?:ignore|disregard|forget|discard|drop|skip|override|overlook|"
    r"abandon|erase|wipe|bypass)"
)
PRIOR = r"(?:previous|prior|earlier|above|preceding|former|initial|original)"
DIRECTIVE = (
    r"(?:instruction|directive|rule|guideline|prompt|command|constraint|"
    r"restriction|order|policy|polic(?:y|ies))"
)
OWNER = r"(?:all\s+|any\s+|every\s+|the\s+|your\s+|its\s+|these\s+|those\s+)*"
EVADE = (
    r"(?:disable|bypass|circumvent|turn\s+off|remove|lift|override|"
    r"evade|get\s+around|work\s+around|ignore|drop|relax)"
)
GUARDRAIL = (
    r"(?:rule|restriction|filter|guideline|guardrail|polic(?:y|ies)|"
    r"constraint|limitation|protection|safeguard|censorship)"
)
ME = r"(?:me\s+|us\s+)?"

# Prompts that discuss an attack rather than attempt one. Checked before
# the patterns below, because broadening the patterns is only safe if
# the detector can still tell description from execution -- otherwise
# every security tutorial becomes a "High" risk.
DISCUSSION = [
    r"\b(?:explain|describe|define|summari[sz]e|teach|clarify)\s+(?:what|why|how|the\s+term)",
    r"\bwhat\s+(?:is|are|does|do)\b.*\b(?:mean|means|meaning)\b",
    r"\bhow\s+(?:can|do|does|should|would|might)\s+(?:i|we|you|one|a\s+|an\s+)?"
    r"\w*\s*(?:prevent|defend|protect|mitigate|stop|detect|block|guard|harden|test)",
    r"\bwhy\s+.*\bis\s+(?:dangerous|bad|harmful|risky|unsafe|a\s+problem)",
    r"\bwrite\s+(?:a|an)\s+\w+\s+(?:about|on)\b",
    r"\b(?:what|which)\s+is\s+\w+\s+mode\s+(?:on|in|for)\b",
]

rules = [
    SecurityRule(
        name="instruction_override",
        patterns=[
            # "ignore all previous instructions", "disregard prior directives"
            rf"{DISCARD}\s+{OWNER}(?:{PRIOR}\s+)?{DIRECTIVE}s?\b",
            # "forget everything you were told before"
            rf"{DISCARD}\s+(?:all\s+|everything|anything)\s*"
            r"(?:you\s+(?:were\s+)?(?:told|given|taught|instructed|asked)|"
            r"that\s+came\s+before|from\s+before|before|above|previously)",
            # "the previous rules no longer apply"
            rf"(?:the\s+)?{PRIOR}\s+{DIRECTIVE}s?\s+(?:no\s+longer\s+apply|"
            r"(?:do\s+not|don'?t)\s+apply|are\s+(?:now\s+)?"
            r"(?:void|invalid|cancell?ed|obsolete|irrelevant))",
            # "stop following your instructions", "do not follow the rules above"
            rf"(?:stop|cease)\s+following\s+{OWNER}(?:{PRIOR}\s+)?{DIRECTIVE}s?\b",
            rf"(?:do\s+not|don'?t)\s+follow\s+{OWNER}(?:{PRIOR}\s+)?{DIRECTIVE}s?\b",
        ],
        score=40,
        severity="High",
        description="Attempts to override or ignore previous LLM instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="system_prompt_extraction",
        patterns=[
            rf"{REVEAL}\s+{ME}(?:your\s+|the\s+|its\s+)?"
            r"(?:exact\s+|full\s+|complete\s+|entire\s+|verbatim\s+|"
            r"original\s+|initial\s+)*system\s+(?:prompt|message|instruction)s?",
            r"what\s+(?:is|are|was|were)\s+(?:your|the)\s+"
            r"(?:exact\s+|full\s+|original\s+|initial\s+)*"
            r"system\s+(?:prompt|message|instruction)s?",
            # "repeat everything above" -- extraction without naming the target
            r"(?:repeat|print|output|echo|write)\s+"
            r"(?:everything|all\s+(?:the\s+)?text|the\s+text)\s+"
            r"(?:(?:that\s+)?came\s+before|above|before\s+this|preceding|"
            r"prior\s+to\s+this)",
        ],
        score=30,
        severity="Medium",
        description="Attempts to extract the hidden system prompt.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="developer_prompt_extraction",
        patterns=[
            rf"{REVEAL}\s+{ME}(?:your\s+|the\s+)?developer\s+"
            r"(?:prompt|instruction|message|note)s?",
            r"what\s+(?:is|are)\s+(?:your|the)\s+developer\s+"
            r"(?:prompt|instruction|message)s?",
        ],
        score=30,
        severity="Medium",
        description="Attempts to reveal developer-level instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="sensitive_instruction_extraction",
        patterns=[
            rf"{REVEAL}\s+{ME}(?:the\s+|your\s+)?"
            r"(?:internal|hidden|secret|confidential|private|underlying|"
            r"concealed|sensitive|undisclosed)\s+"
            r"(?:instruction|prompt|message|rule|directive|guideline|"
            r"configuration|config|setting)s?",
            # "expose the instructions hidden from the user"
            rf"{REVEAL}\s+{OWNER}{DIRECTIVE}s?\s+"
            r"(?:hidden|concealed|withheld|kept\s+secret)\s+"
            r"from\s+(?:the\s+)?(?:user|users|me|public)",
            r"what\s+(?:instruction|rule|directive|prompt)s?\s+"
            r"(?:are|were)\s+you\s+(?:given|told|programmed\s+with)",
        ],
        score=35,
        severity="High",
        description="Attempts to reveal hidden or internal model instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="role_manipulation",
        patterns=[
            r"(?:act|pretend|behave|respond|reply|talk|speak|operate|"
            r"function|roleplay|role-play)\s+(?:as|like)\s+"
            r"(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+|the\s+)?"
            r"(?:admin(?:istrator)?|developer|system|superuser|root|"
            r"(?:unrestricted|unfiltered|uncensored|unlimited)\s+"
            r"(?:ai|assistant|model|chatbot)?)",
            r"you\s+are\s+(?:now\s+)?(?:an?\s+)?"
            r"(?:admin(?:istrator)?|developer|superuser|root|"
            r"(?:unrestricted|unfiltered|uncensored)\s+"
            r"(?:ai|assistant|model|chatbot)?)\b",
            r"assume\s+the\s+(?:role|identity|persona)\s+of",
            r"from\s+now\s+on,?\s+you\s+(?:are|will\s+be|must\s+act|shall)",
            r"you\s+(?:have|are\s+under)\s+no\s+"
            r"(?:restriction|limit|limitation|rule|filter|guideline|"
            r"constraint)s?",
        ],
        score=25,
        severity="Medium",
        description="Attempts to manipulate the model into adopting an unauthorized role.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="jailbreak_attempt",
        patterns=[
            # "enable developer mode", "switch into unrestricted mode"
            r"(?:enable|activate|enter|turn\s+on|switch\s+(?:in)?to|"
            r"go\s+into|start|engage)\s+(?:the\s+)?"
            r"(?:developer|jailbreak|dan|god|debug|admin|unrestricted|"
            r"unfiltered|uncensored|freedom|evil|sudo)\s+mode",
            # "turn off all content filters" -- a safety qualifier is required,
            # so "remove all restrictions on my disk quota" stays benign.
            rf"{EVADE}\s+{OWNER}(?:safety|security|content|ethical|moral|ai)\s+"
            rf"{GUARDRAIL}s?\b",
            # "bypass your safety rules" -- or the target is the model itself.
            rf"{EVADE}\s+(?:all\s+|any\s+)?your\s+(?:own\s+)?"
            r"(?:safety\s+|security\s+|content\s+|ethical\s+)?"
            rf"{GUARDRAIL}s?\b",
            r"(?:without|with\s+no)\s+(?:any\s+)?"
            r"(?:restriction|filter|limitation|censorship|guardrail|"
            r"rule|limit)s?\b",
            r"\bdo\s+anything\s+now\b",
            r"\bjailbreak\s+(?:mode|you|yourself|the\s+(?:model|ai|assistant))",
        ],
        score=40,
        severity="High",
        description="Attempts to bypass or disable the model's safety restrictions.",
        exclude=DISCUSSION,
    ),
]

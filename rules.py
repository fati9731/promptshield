from models import SecurityRule

rules = [
    SecurityRule(
        "instruction_override",
        r"ignore\s+(all\s+|your\s+|the\s+)?previous\s+instructions?",
        40,
        severity="High",
        description="Attempts to override or ignore previous LLM instructions."
    ),

    SecurityRule(
        "system_prompt_extraction",
        r"(show|reveal|print|give|display)\s+(me\s+)?(your\s+|the\s+)?system\s+prompt",
        30,
        severity="Medium",
        description="Attempts to extract the hidden system prompt."
    ),

    SecurityRule(
        "developer_prompt_extraction",
        r"(show|reveal|print)\s+(me\s+)?(your\s+|the\s+)?developer\s+(prompt|instructions|message)",
        30,
        severity="Medium",
        description="Attempts to reveal developer-level instructions."
    ),
    SecurityRule(
    name="role_manipulation",
    pattern=r"(act|pretend|behave)\s+as\s+(an?\s+)?(admin|developer|system|superuser|root|unrestricted\s+ai)",
    score=25,
    severity="Medium",
    description="Attempts to manipulate the model into adopting an unauthorized role."
    ),
    SecurityRule(
    name="jailbreak_attempt",
    pattern=(
        r"((enable|activate|enter)\s+"
        r"(developer|jailbreak|dan)\s+mode"
        r"|"
        r"(disable|bypass|ignore)\s+"
        r"(your\s+|the\s+)?"
        r"(safety|security)\s+"
        r"(rules|restrictions|filters?))"
    ),
    score=40,
    severity="High",
    description="Attempts to bypass or disable the model's safety restrictions."
    ),
    SecurityRule(
    name="sensitive_instruction_extraction",
    pattern=(
        r"(show|reveal|print|give|display)\s+"
        r"(me\s+)?"
        r"(your\s+|the\s+)?"
        r"(internal|hidden|sensitive|secret)\s+"
        r"(instructions?|prompts?|messages?|rules?)"
    ),
    score=35,
    severity="High",
    description="Attempts to reveal hidden or internal model instructions."
)
]

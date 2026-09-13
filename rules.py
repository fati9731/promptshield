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
    )
]
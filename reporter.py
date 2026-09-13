def format_result(prompt, score, risk_level, detected_rules):
    result = (
        f"Prompt: {prompt}\n"
        f"Score: {score}\n"
        f"Risk Level: {risk_level}\n"
    )

    if detected_rules:
        result += "Detected rules:\n"

        for rule in detected_rules:
            result += (
                f"- {rule.name} (Score: {rule.score}, Severity: {rule.severity})\n"
                f"  Description: {rule.description}\n"
            )

    else:
        result += "Detected rules: None\n"

    result += "\n----------------------------------------\n\n"

    return result
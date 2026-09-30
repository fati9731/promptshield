SEPARATOR = "\n----------------------------------------\n\n"


def format_rule_details(detected_rules):
    if not detected_rules:
        return "Detected rules: None\n"

    block = "Detected rules:\n"

    for rule in detected_rules:
        block += (
            f"- {rule.name} (Score: {rule.score}, Severity: {rule.severity})\n"
            f"  Description: {rule.description}\n"
        )

    return block


def format_result(prompt, score, risk_level, detected_rules):
    return (
        f"Prompt: {prompt}\n"
        f"Score: {score}\n"
        f"Risk Level: {risk_level}\n"
        + format_rule_details(detected_rules)
        + SEPARATOR
    )


def _verdict(flagged):
    return "MALICIOUS" if flagged else "SAFE"


def format_analysis(result):
    """Render a HybridDetector result: both detectors and their union."""
    lines = [
        f"Prompt: {result['prompt']}",
        "",
        f"Rule Engine:     {_verdict(result['rule_decision'])}",
    ]

    if result["ml_available"]:
        lines += [
            f"ML Probability:  {result['ml_probability']:.3f}",
            f"ML Decision:     {_verdict(result['ml_decision'])}",
        ]
    else:
        lines += ["ML Probability:  unavailable (rules only)"]

    lines += [
        f"Hybrid Decision: {_verdict(result['hybrid_decision'])}",
        "",
        f"Risk: {result['risk']}",
        "",
    ]

    return (
        "\n".join(lines)
        + format_rule_details(result["detected_rules"])
        + SEPARATOR
    )

def format_summary(stats, title="Analysis Summary"):
    return (
        f"\n{title}\n"
        "========================\n"
        f"Total prompts: {stats['total']}\n"
        f"Safe: {stats['Safe']}\n"
        f"Low: {stats['Low']}\n"
        f"Medium: {stats['Medium']}\n"
        f"High: {stats['High']}\n"
        f"rules_detected: {stats['threats']}\n"
    )

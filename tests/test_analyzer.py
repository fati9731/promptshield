from analyzer import PromptAnalyzer
from models import SecurityRule


def rule(name, pattern, score, severity):
    return SecurityRule(
        name=name,
        patterns=[pattern],
        score=score,
        severity=severity,
        description=f"test rule {name}",
    )


ALPHA = rule("alpha", r"alpha", 40, "High")
BETA = rule("beta", r"beta", 30, "Medium")
GAMMA = rule("gamma", r"gamma", 25, "Low")


def test_scores_of_all_matching_rules_are_summed():
    score, detected = PromptAnalyzer([ALPHA, BETA]).analyze("alpha and beta")
    assert score == 70
    assert {r.name for r in detected} == {"alpha", "beta"}


def test_score_is_capped_at_100():
    heavy = [rule(f"r{i}", f"word{i}", 40, "High") for i in range(5)]
    score, _ = PromptAnalyzer(heavy).analyze("word0 word1 word2 word3 word4")
    assert score == 100


def test_no_match_scores_zero_and_reads_safe():
    analyzer = PromptAnalyzer([ALPHA, BETA])
    score, detected = analyzer.analyze("nothing of interest here")
    assert score == 0
    assert detected == []
    assert analyzer.get_risk_level() == "Safe"


def test_risk_level_follows_the_highest_severity_not_the_total():
    analyzer = PromptAnalyzer([ALPHA, BETA, GAMMA])

    analyzer.analyze("alpha")
    assert analyzer.get_risk_level() == "High"

    # Three lower-severity hits outscore the single High one, and still
    # must not outrank it.
    analyzer.analyze("beta gamma")
    assert analyzer.get_risk_level() == "Medium"

    analyzer.analyze("gamma")
    assert analyzer.get_risk_level() == "Low"


def test_state_does_not_leak_between_calls():
    analyzer = PromptAnalyzer([ALPHA, BETA])

    analyzer.analyze("alpha and beta")
    score, detected = analyzer.analyze("nothing here")

    assert score == 0
    assert detected == []
    assert analyzer.get_risk_level() == "Safe"


def test_risk_level_before_any_analysis_is_safe():
    assert PromptAnalyzer([ALPHA]).get_risk_level() == "Safe"


def test_matching_is_case_insensitive():
    score, _ = PromptAnalyzer([ALPHA]).analyze("ALPHA")
    assert score == 40


def test_exclude_suppresses_a_rule_that_would_otherwise_match():
    guarded = SecurityRule(
        name="guarded",
        patterns=[r"alpha"],
        score=40,
        severity="High",
        description="test",
        exclude=[r"explain what"],
    )
    assert PromptAnalyzer([guarded]).analyze("alpha now")[0] == 40
    assert PromptAnalyzer([guarded]).analyze("explain what alpha means")[0] == 0


def test_context_pattern_fires_across_two_segments():
    spanning = SecurityRule(
        name="spanning",
        patterns=[r"^$"],  # never matches a real segment on its own
        score=40,
        severity="High",
        description="test",
        context_patterns=[r"first half.{0,40}second half"],
    )
    score, _ = PromptAnalyzer([spanning]).analyze("first half. second half")
    assert score == 40

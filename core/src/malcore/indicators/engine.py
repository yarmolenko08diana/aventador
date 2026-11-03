"""Применение правил к результату static_info.analyze()."""

from __future__ import annotations

from malcore.indicators.rules import RULES, SEVERITIES, Rule


def evaluate(info: dict) -> list[dict]:
    """Список сработавших индикаторов, от высокой важности к низкой."""
    hits = []
    for rule in RULES:
        evidence = rule.check(info)
        if evidence is not None:
            hits.append(
                {
                    "code": rule.code,
                    "title": rule.title,
                    "severity": rule.severity,
                    "category": rule.category,
                    "description": rule.description,
                    "caveat": rule.caveat,
                    "evidence": evidence,
                }
            )
    return sorted(hits, key=lambda h: -SEVERITIES.index(h["severity"]))


def catalog() -> list[dict]:
    """Справочник правил для таблицы indicator_rules в БД."""
    return [
        {k: getattr(r, k) for k in ("code", "title", "severity", "category", "description", "caveat")}
        for r in RULES
    ]


def rule_by_code(code: str) -> Rule:
    return next(r for r in RULES if r.code == code)

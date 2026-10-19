from ..defaults import RULES
from ..errors import ApiError
from ..services import settings as st
from ..validators import integer, invalid, json_body
from . import bp

LIMITS = {"threshold": (1, 10000), "windowSeconds": (1, 3600), "cooldownSeconds": (0, 86400)}
SETTING_NAMES = {"threshold": "threshold", "windowSeconds": "window_seconds", "cooldownSeconds": "cooldown_seconds"}


def _rule(rule_id: str) -> dict:
    meta = RULES[rule_id]
    return {"id": rule_id, "name": meta["name"], "category": meta["category"], "description": meta["description"],
            "editable": meta["editable"], "severity": st.get(f"severity.{meta['category']}"),
            **st.rule_params(rule_id)}


@bp.get("/rules")
def list_rules():
    return {"items": [_rule(r) for r in RULES]}


@bp.put("/rules/<rule_id>")
def save_rule(rule_id):
    if rule_id not in RULES:
        raise ApiError(404, "not_found", "Unknown rule.")
    data = json_body()
    updates = {}
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise invalid("enabled", "Must be true or false.")
        updates[f"rule.{rule_id}.enabled"] = "1" if data["enabled"] else "0"
    for field, (low, high) in LIMITS.items():
        if field in data:
            if field not in RULES[rule_id]["editable"]:
                raise invalid(field, "This setting cannot be edited for this rule.")
            updates[f"rule.{rule_id}.{SETTING_NAMES[field]}"] = integer(data[field], field, low, high)
    unknown = set(data) - {"enabled", *LIMITS}
    if unknown:
        raise invalid(sorted(unknown)[0], "Unknown field.")
    if not updates:
        raise invalid("body", "Nothing to update.")
    st.set_many(updates)
    return _rule(rule_id)

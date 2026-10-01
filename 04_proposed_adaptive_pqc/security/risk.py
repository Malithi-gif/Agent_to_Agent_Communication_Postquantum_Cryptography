def classify_risk(action: str) -> str:
    action = action.lower().strip()
    if action in {"payment", "purchase", "book_flight", "transfer_money"}:
        return "CRITICAL"
    if action in {"read_calendar", "check_calendar", "modify_calendar"}:
        return "MEDIUM"
    if action in {"search_flight", "get_flight", "discover_agent"}:
        return "LOW"
    return "CRITICAL"

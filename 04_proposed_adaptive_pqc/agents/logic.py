def flight_response(payload):
    origin = payload["origin"].upper()
    destination = payload["destination"].upper()
    date = payload["date"]
    return {
        "agent": "flight",
        "status": "success",
        "flights": [
            {"flight_id": "AA123", "origin": origin, "destination": destination,
             "date": date, "price": 425.0, "departure": "09:30"},
            {"flight_id": "UA456", "origin": origin, "destination": destination,
             "date": date, "price": 489.0, "departure": "13:20"},
            {"flight_id": "DL789", "origin": origin, "destination": destination,
             "date": date, "price": 535.0, "departure": "17:40"},
        ],
    }

def calendar_response(payload):
    return {
        "agent": "calendar",
        "status": "success",
        "date": payload["date"],
        "available": True,
        "conflicts": [],
    }

def payment_response(payload):
    import uuid
    amount = float(payload["amount"])
    if amount <= 0:
        raise ValueError("Invalid payment amount")
    return {
        "agent": "payment",
        "status": "approved",
        "transaction_id": f"SIM-{uuid.uuid4().hex[:10].upper()}",
        "flight_id": payload["flight_id"],
        "amount": amount,
    }

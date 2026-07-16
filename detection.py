from models import ScanStatus


def run_detection(message: str) -> dict:
    text_upper = message.upper()
    risk = 0
    category = "Legitimate"
    reason = "No suspicious patterns detected."
    confidence = "Low"

    # OTP / PIN theft
    if "OTP" in text_upper or "PIN" in text_upper:
        risk += 40
        category = "OTP Theft"
        reason = "Request for sensitive OTP or PIN detected."
        confidence = "High"

    # Urgency tactics
    if "URGENT" in text_upper or "IMMEDIATELY" in text_upper or "SUSPENDED" in text_upper:
        risk += 30
        if category == "Legitimate":
            category = "Urgency Scam"
        reason += " Urgency language detected."

    # Mobile Money spoofing
    if "MTN" in text_upper or "ORANGE" in text_upper or "MOMO" in text_upper:
        risk += 20
        if category == "Legitimate":
            category = "Fake Mobile Money Alert"
        reason += " Spoofed Mobile Money reference."

    # Suspicious links
    if "http" in message.lower() or "www." in message.lower():
        risk += 25
        if category == "Legitimate":
            category = "Phishing Link"
        reason += " Suspicious link detected."

    # Lottery / prize scams
    if "WINNER" in text_upper or "PRIZE" in text_upper or "LOTTERY" in text_upper:
        risk += 25
        if category == "Legitimate":
            category = "Lottery Scam"
        reason += " Fake prize offer."

    risk = min(risk, 100)

    if risk < 25:
        status = ScanStatus.SAFE
    elif risk < 60:
        status = ScanStatus.SUSPICIOUS
    else:
        status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": status,
        "scam_category": category,
        "reason": reason,
        "confidence_level": 0.9 if confidence == "High" else 0.5,
    }            category = "Phishing Link"
        reason += " Suspicious link detected."

    if "WINNER" in text_upper or "PRIZE" in text_upper or "LOTTERY" in text_upper:
        risk += 25
        if category == "Legitimate":
            category = "Lottery Scam"
        reason += " Fake prize offer."

    risk = min(risk, 100)

    if risk < 25:
        status = ScanStatus.SAFE
    elif risk < 60:
        status = ScanStatus.SUSPICIOUS
    else:
        status = ScanStatus.SCAM

    return {
        "risk_score": risk,
        "status": status,
        "scam_category": category,
        "reason": reason,
        "confidence_level": 0.9 if confidence == "High" else 0.5,
    }

# =============================================================================
# STUB (replace with the real engine above)
# =============================================================================
# def run_detection(message: str) -> dict:
#     return {
#         "risk_score": 0,
#         "status": ScanStatus.SAFE,
#         "scam_category": None,
#         "reason": "Detection engine not yet implemented.",
#         "confidence_level": 0.0,
#     }

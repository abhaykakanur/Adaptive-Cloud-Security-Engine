# app/security/trust_manager.py


def update_trust(user, risk):

    if risk == "LOW":
        user.trust_score += 2

    elif risk == "MEDIUM":
        user.trust_score -= 1

    else:
        user.trust_score -= 5

    if user.trust_score < 0:
        user.trust_score = 0

    if user.trust_score > 100:
        user.trust_score = 100
import pandas as pd


def analyze_logs(data):
    results = []

    for user in data["user"].unique():
        user_logs = data[data["user"] == user]

        failed_logins = len(
            user_logs[
                (user_logs["event_type"] == "Login") &
                (user_logs["status"] == "Failed")
            ]
        )

        successful_logins = len(
            user_logs[
                (user_logs["event_type"] == "Login") &
                (user_logs["status"] == "Success")
            ]
        )

        sensitive_access = len(
            user_logs[
                (user_logs["event_type"] == "File_Access") &
                (user_logs["status"] == "Sensitive")
            ]
        )

        internal_connections = len(
            user_logs[
                (user_logs["event_type"] == "Network_Connection") &
                (user_logs["status"] == "Internal")
            ]
        )

        privilege_attempts = len(
            user_logs[
                (user_logs["event_type"] == "Privilege_Change")
            ]
        )

        risk_score = 0
        reasons = []

        if failed_logins >= 3:
            risk_score += 25
            reasons.append("Multiple failed login attempts")

        if successful_logins > 0 and failed_logins >= 3:
            risk_score += 20
            reasons.append("Successful login after repeated failures")

        if sensitive_access > 0:
            risk_score += 20
            reasons.append("Sensitive file access detected")

        if internal_connections > 0:
            risk_score += 15
            reasons.append("Internal network activity detected")

        if privilege_attempts > 0:
            risk_score += 20
            reasons.append("Privilege change attempt detected")

        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        results.append({
            "user": user,
            "risk_score": min(risk_score, 100),
            "risk_level": risk_level,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "sensitive_access": sensitive_access,
            "internal_connections": internal_connections,
            "privilege_attempts": privilege_attempts,
            "reasons": reasons
        })

    return results
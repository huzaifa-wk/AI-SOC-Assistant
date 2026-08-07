def get_threat_rating(score):

    if score <= 20:

        return "🟢 SAFE"

    elif score <= 60:

        return "🟡 SUSPICIOUS"

    else:

        return "🔴 MALICIOUS"
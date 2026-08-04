from parser import load_alert


def main():

    alert = load_alert("../sample_alerts/ssh_bruteforce.json")

    print("========== WAZUH ALERT ==========\n")

    print(f"Rule ID      : {alert['rule']['id']}")
    print(f"Rule Level   : {alert['rule']['level']}")
    print(f"Description  : {alert['rule']['description']}")
    print(f"Agent        : {alert['agent']['name']}")
    print(f"Source IP    : {alert['srcip']}")
    print(f"Timestamp    : {alert['timestamp']}")
    print(f"MITRE IDs    : {', '.join(alert['mitre']['id'])}")
    print(f"Tactics      : {', '.join(alert['mitre']['tactic'])}")


if __name__ == "__main__":
    main()

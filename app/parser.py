import json


def load_alert(file_path):
    """
    Load a Wazuh alert from a JSON file.
    """

    with open(file_path, "r") as file:
        alert = json.load(file)

    return alert

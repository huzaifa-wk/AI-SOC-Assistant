import json


def load_alert(file_path):
    """
    Load a Wazuh alert from a JSON file.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)
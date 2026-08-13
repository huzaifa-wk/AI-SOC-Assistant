import json
from pathlib import Path


def load_alert(file_path):
    """
    Load and validate a Wazuh alert from a JSON file.

    Args:
        file_path: Path to the Wazuh alert JSON file.

    Returns:
        dict: Parsed Wazuh alert.

    Raises:
        FileNotFoundError: If the alert file does not exist.
        ValueError: If the JSON does not contain an object.
        json.JSONDecodeError: If the file contains invalid JSON.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Wazuh alert file not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        alert = json.load(file)

    if not isinstance(alert, dict):
        raise ValueError(
            "Wazuh alert must be a JSON object."
        )

    return alert
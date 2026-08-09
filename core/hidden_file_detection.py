import os
import stat


def check_hidden_file(file_path):
    """
    Checks whether a file has the Windows "Hidden" attribute set.

    Returns a dictionary with:
        - is_hidden: True/False
        - anomaly_detected: True/False (same as is_hidden, kept for
          consistency with our other analysis modules)
        - explanation: description of the finding
    """
    file_stat = os.stat(file_path)

    # On Windows, st_file_attributes contains attribute flags.
    # FILE_ATTRIBUTE_HIDDEN = 0x2 (bit flag for "hidden")
    is_hidden = bool(file_stat.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)

    if is_hidden:
        explanation = (
            "Observation: file has the Hidden attribute set. This alone "
            "is not necessarily suspicious (many legitimate files are "
            "hidden), but combined with other indicators may warrant "
            "investigator review."
        )
    else:
        explanation = "File does not have the Hidden attribute set."

    return {
        "is_hidden": is_hidden,
        "anomaly_detected": is_hidden,
        "explanation": explanation
    }
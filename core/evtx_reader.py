from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime


def read_evtx_file(file_path):
    """
    Reads a real Windows .evtx file and converts each event into
    our standard dictionary format:
        { "event_id": int, "timestamp": datetime, "source": str, "message": str }

    This lets us feed REAL event log data into our existing,
    already-tested analyze_event_log() function without changing
    that function's logic at all.
    """
    events = []

    # XML namespace used inside every Windows event record
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    with Evtx(file_path) as log:
        for record in log.records():
            xml_string = record.xml()
            root = ET.fromstring(xml_string)

            # Extract Event ID
            event_id_elem = root.find(f".//{ns}EventID")
            event_id = int(event_id_elem.text) if event_id_elem is not None else -1

            # Extract Timestamp
            time_elem = root.find(f".//{ns}TimeCreated")
            timestamp_str = time_elem.attrib.get("SystemTime") if time_elem is not None else None
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "")) if timestamp_str else None

            # Extract Source (Provider Name)
            provider_elem = root.find(f".//{ns}Provider")
            source = provider_elem.attrib.get("Name") if provider_elem is not None else "Unknown"

            # Build a simple message summary (just note it came from real data)
            message = f"Real event extracted from {file_path}"

            events.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "source": source,
                "message": message
            })

    return events
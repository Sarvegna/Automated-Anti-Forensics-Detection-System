try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None
import xml.etree.ElementTree as ET
from datetime import datetime


def read_evtx_file(file_path):
    """
    Reads a real Windows .evtx file and converts each event into
    our standard dictionary format:
        {
            "event_id": int,
            "record_id": int,
            "channel": str,
            "computer": str,
            "timestamp": datetime,
            "source": str,
            "message": str
        }
    """
    if Evtx is None:
        raise ImportError("python-evtx package is not installed.")
    events = []

    # XML namespace used inside every Windows event record
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    with Evtx(file_path) as log:
        for record in log.records():
            xml_string = record.xml()
            root = ET.fromstring(xml_string)

            # Extract Event ID strictly from System element
            event_id_elem = root.find(f"./{ns}System/{ns}EventID")
            if event_id_elem is None:
                event_id_elem = root.find(f".//{ns}EventID")

            if event_id_elem is not None and event_id_elem.text:
                try:
                    event_id = int(event_id_elem.text.strip())
                except ValueError:
                    event_id = -1
            else:
                event_id = -1

            # Extract Event Record ID
            rec_elem = root.find(f"./{ns}System/{ns}EventRecordID")
            if rec_elem is None:
                rec_elem = root.find(f".//{ns}EventRecordID")

            if rec_elem is not None and rec_elem.text and rec_elem.text.strip().isdigit():
                record_id = int(rec_elem.text.strip())
            else:
                try:
                    record_id = record.record_num()
                except Exception:
                    record_id = None

            # Extract Channel (Log Name)
            chan_elem = root.find(f"./{ns}System/{ns}Channel")
            if chan_elem is None:
                chan_elem = root.find(f".//{ns}Channel")
            channel = chan_elem.text.strip() if chan_elem is not None and chan_elem.text else "Security"

            # Extract Computer
            comp_elem = root.find(f"./{ns}System/{ns}Computer")
            if comp_elem is None:
                comp_elem = root.find(f".//{ns}Computer")
            computer = comp_elem.text.strip() if comp_elem is not None and comp_elem.text else "Unknown"

            # Extract Timestamp
            time_elem = root.find(f"./{ns}System/{ns}TimeCreated")
            if time_elem is None:
                time_elem = root.find(f".//{ns}TimeCreated")
            timestamp_str = time_elem.attrib.get("SystemTime") if time_elem is not None else None
            timestamp = None
            if timestamp_str:
                try:
                    ts_clean = timestamp_str.replace("Z", "+00:00")
                    timestamp = datetime.fromisoformat(ts_clean)
                except Exception:
                    try:
                        timestamp = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        timestamp = None

            # Extract Source (Provider Name)
            provider_elem = root.find(f"./{ns}System/{ns}Provider")
            if provider_elem is None:
                provider_elem = root.find(f".//{ns}Provider")
            source = provider_elem.attrib.get("Name") if provider_elem is not None else "Unknown"

            # Preserve available EventData instead of replacing it with a
            # generic parser message.  Detection still relies only on the
            # numeric Event ID extracted above.
            event_data = {}
            event_data_elem = root.find(f"./{ns}EventData")
            if event_data_elem is not None:
                for index, data_elem in enumerate(event_data_elem.findall(f"{ns}Data")):
                    field_name = data_elem.attrib.get("Name") or f"Data{index + 1}"
                    event_data[field_name] = (data_elem.text or "").strip()

            message = "; ".join(
                f"{field_name}={value}"
                for field_name, value in event_data.items()
                if value
            )
            if not message:
                message = f"Event ID {event_id} recorded in {channel}."

            events.append({
                "event_id": event_id,
                "record_id": record_id,
                "channel": channel,
                "computer": computer,
                "timestamp": timestamp,
                "source": source,
                "message": message,
                "event_data": event_data
            })

    return events

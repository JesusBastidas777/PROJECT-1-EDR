


import win32evtlog

from collectors.process_parser import parse_event_xml

from detectors.process_detector import detect_suspicious_process

from detectors.network_detector import detect_suspicious_network

from detectors.persistence_detector import detect_persistence

from detectors.powershell_detector import detect_suspicious_powershell

from detectors.credential_dumping_detector import detect_credential_dumping

from pipeline.parser import parse_event

from pipeline.pipeline_event_router import route_event

from pipeline.normalizer import normalize_event

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

def get_raw_sysmon_events(max_events = 5) :

    query = "*"

    handle = win32evtlog.EvtQuery(LOG_NAME, win32evtlog.EvtQueryReverseDirection, query)

    events = win32evtlog.EvtNext(handle,max_events)

    parsed_events = []

    for event in events :

        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

        parsed = parse_event_xml(xml)

        parsed = parse_event(parsed)

        parsed = route_event(parsed)

        parsed = normalize_event(parsed)

        alert = detect_suspicious_process(parsed)

        network_alert = detect_suspicious_network(parsed)

        persistence_alert = detect_persistence(parsed)

        powershell_alert = detect_suspicious_powershell(parsed)
        credential_alert = detect_credential_dumping(parsed)

        if alert :

            print("=" * 80)

            print("ALERT DETECTED")

            print(alert)

            with open("alerts.log", "a") as log_file :

                log_file.write(str(alert) + "\n")

        if network_alert :

            print("=" * 80)
            print("NETWORK ALERT DETECTED")
            print(network_alert)

        if persistence_alert :

            print("=" * 80)
            print("PERSISTENCE ALERT DETECTED")
            print(persistence_alert)

        if powershell_alert :

            print("=" * 80)
            print("POWERSHELL ALERT DETECTED")
            print(powershell_alert)

        if credential_alert :
            print("=" * 80)
            print("CREDENTIAL DUMPING DETECTED")
            print(credential_alert)



        parsed_events.append(parsed)

    return parsed_events

if __name__ == "__main__" :

    events = get_raw_sysmon_events()

    for event in events :

        print("=" * 80)

        print(event)

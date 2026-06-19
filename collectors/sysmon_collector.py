


import win32evtlog

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

def get_sysmon_events(max_events = 20) :

    events_data = []

    hand = win32evtlog.OpenEventLog(None, LOG_NAME)

    flags = (win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ)

    events = win32evtlog.ReadEventLog(hand,flags,0)

    count = 0 

    while events and count < max_events :

        for event in events :

            try :

                event_info = {"event_id": event.EventID & 0xFFFF, "source": event.SourceName, "time_generated" : str(event.TimeGenerated), "computer" : event.ComputerName, "record_number" : event.RecordNumber, "category": event.EventCategory, "event_type" : event.EventType, "strings": event.StringInserts}

                events_data.append(event_info)

                count += 1

                if count >= max_events:

                    break

            except Exception:

                continue

        events = win32evtlog.ReadEventLog(hand, flags, 0)

    return events_data
        
if __name__ == "__main__" :
    
    logs = get_sysmon_events()
    
    for log in logs :
        
        print("=" * 80)
        
        print(f"EVENT ID : {log['event_id']}")
        
        print(f"TIME : {log['time_generated']}")
        
        print(f"SOURCE : {log['source']}")
        
        print(f"COMPUTER : {log['computer']}")

        print(f"RECORD : {log['record_number']}")

        print(f"STRINGS : {log['strings']}")



def detect_persistence(event) :

    image = event.get("Image","").lower()

    command_line = event.get("CommandLine","").lower()

    persistence_keywords = [

        "currentversion\\run",
        "currentversion\\runonce",
        "startup",
        "schtasks",
        "scheduledtask"
    ]

    for keyword in persistence_keywords :

        if keyword in command_line :

            return {

                "alert" : "Persistence Activity Detected", "severity" : "high", "technique" : "T1547", "keyword" : keyword, "process" : image
            }
        
    return None 




def detect_credential_dumping(event) :

    command_line = event.get("CommandLine","").lower()

    suspicious_keywords = [

        "mimikatz",
        "procdump",
        "lsass",
        "comsvcs.dll"
    ]

    for keyword in suspicious_keywords :

        if keyword in command_line :

            return {
                "alert" : "Credential Dumping Detected", "severity" : "critical", "technique" : "T1003", "keyword" :  keyword
            }

    return None 









def detect_suspicious_powershell(event) :

    command_line = event.get("CommandLine","").lower()

    suspicious_keywords = [

        "-enc",
        "-encodedcommand",
        "-nop",
        "-w hidden",
        "iex",
        "invoke-expression"
    ]

    for keyword in suspicious_keywords :

        if keyword in command_line :

            return {

                "alert" : "Suspicious PowerShell Activity", "severity" : "high", "technique" : "T1059.001", "keyword" : keyword
            }
        
    return None
    
    
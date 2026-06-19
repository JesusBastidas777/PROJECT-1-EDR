


def detect_suspicious_network(event) :

    destination_ip = event.get("DestinationIp","")

    if not destination_ip :

        return None 
    
    suspicious_ips = [

        "185",
        "91",
        "103"
    ]

    for ip in suspicious_ips :

        if destination_ip.startswith(ip) :

            return {

                "alert" : "Suspicious Network Conection", "severity": "high", "technique" : "T1071", "destination_ip" : destination_ip
 
            }
    
    return None 
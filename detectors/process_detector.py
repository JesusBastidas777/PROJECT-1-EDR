


import time

from config.settings import (

    CPU_THRESHOLD,
    SAFE_PROCESSES,
    NOISE_PROCESSES,
    SYSTEM_PROCESSES,
    SPIKE_THRESHOLD,
    SHORT_LIFE_SECONDS,
    SUSPICIOUS_NAMES,
    PROCESS_BURST_THRESHOLD,
    PROCESS_BURST_WINDOW,
    RESPAWN_THRESHOLD,
    RESPAWN_WINDOW,
    SUSPICIOUS_PATHS,
    SUSPICIOUS_COMMANDS,
    SUSPICIOUS_PARENTS,
    KNOWN_MALICIOUS_HASHES,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_USERS

)

from state import (

    previous_pid,
    initialized,
    cpu_history,
    first_seen,
    last_seen,
    threat_stats,
    new_process_times,
    respawn_tracker,

)

from os.path import splitext

def detect_suspicious_process(event) :

    suspicious_process = [

        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe"
    ]

    image = event.get("Image")

    parent_image = event.get("ParentImage", "")

    destination_ip = event.get("DestinationIp","")

    command_line = event.get("CommandLine","")

    if not image:

        return None

    image = image.lower()

    parent_image = parent_image.lower()

    command_line = command_line.lower()

    destination_ip = destination_ip.lower()

    for process in suspicious_process :

        if process in image or process in parent_image :

            return {

                "alert" : "Suspicious Process Detected", "severity" : "medium", "technique" : "T1059" ,  "process" : image, "parent" : parent_image
            }

    if "-enc" in command_line :

        return {

            "alert" : "Suspicious Commandline Detected", "severity" : "high" , "technique" : "T1059" , "commandline" : command_line 
        }

    suspicious_ips = [

        "185",
        "91",
        "103"
    ]

    for ip in suspicious_ips :

        if destination_ip.startswith(ip) :

            return {

                "alert" : "suspicious Network Conecction" , "severity" : "high", "technique" : "T1071", "destination_ip" : destination_ip, "process" : image
            }

    return None

def detect(processes):

    alerts = []

    for p in processes:

        event = {

            "Image": p.get("name"),

            "ParentImage": p.get("parent", ""),

            "CommandLine": p.get("cmdline", ""),

            "DestinationIp": p.get("ip", "")

        }

        result = detect_suspicious_process(event)

        if result:

            alerts.append({

                "pid": p.get("pid"),

                "name": p.get("name"),

                "score": 7, #default baseline

                "reason": result["alert"],

                "level": result["severity"].upper()

            })

    return alerts

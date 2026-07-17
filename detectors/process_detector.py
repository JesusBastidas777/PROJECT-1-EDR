


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
    SUSPICIOUS_USERS,
    SCORE_SUSPICIOUS_PROCESS,
    SCORE_ENCODED_COMMAND,
    SCORE_SUSPICIOUS_IP,
    SUSPICIOUS_PROCESSES,
    SUSPICIOUS_IP_PREFIXES

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

    image = event.get("Image")

    parent_image = event.get("ParentImage", "")

    destination_ip = event.get("DestinationIp","")

    command_line = event.get("CommandLine","")

    score = 0

    reasons = []

    severity = "low"

    if not image:

        return None

    image = image.lower()

    parent_image = parent_image.lower()

    command_line = command_line.lower()

    destination_ip = destination_ip.lower()

    for process in SUSPICIOUS_PROCESSES:

        if process in image or process in parent_image:

            score += SCORE_SUSPICIOUS_PROCESS

            reasons.append("Suspicious Process")

    arguments = command_line.split()

    for command in SUSPICIOUS_COMMANDS:

        if command in arguments:

            score += SCORE_ENCODED_COMMAND

            reasons.append(f"Suspicious Command: {command}")

    for ip in SUSPICIOUS_IP_PREFIXES :

        if destination_ip.startswith(ip) :

            score += SCORE_SUSPICIOUS_IP

            reasons.append("Supicious Network Connection")

    if score >= 7:
        severity = "high"

    elif score >= 4:
        severity = "medium"

    elif score > 0:
        severity = "low"

    if score > 0:
        return {
            "alert": ", ".join(reasons),
            "severity": severity,
            "score": score,
            "technique": "T1059",
            "process": image
        }

    return None

def detect(processes):

    alerts = []

    for p in processes:

        event = {

    "Image": p.get("name"),

    "ParentImage": p.get("parent_name", ""),

    "CommandLine": p.get("cmdline", ""),

    "DestinationIp": p.get("ip", ""),

    "Exe": p.get("exe", ""),

    "Hash": p.get("hash", ""),

    "Username": p.get("username", "")

        }

        result = detect_suspicious_process(event)

        if result:

            alerts.append({

                "pid": p.get("pid"),

                "name": p.get("name"),

                "score": result["score"],

                "reason": result["alert"],

                "level": result["severity"].upper()
            })

    return alerts

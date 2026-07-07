



from response.kill_process import kill_process

AUTO_KILL_THRESHOLD = 7

AUTO_CRITICAL_THRESHOLD = 9

def handle_alerts(alerts, processes,dry_run=False):

    """
    EDR Automatic Response Engine
    """

    actions = []

    for alert in alerts:

        score = alert.get("score", 0 )

        pid = alert.get("pid")

        name = alert.get("name")

        if score >= AUTO_KILL_THRESHOLD:

            if dry_run:

                actions.append({

                "action": "DRY_RUN_KILL",
                "pid": pid,
                "name": name,
                "reason": alert.get("reason")

                })

                continue

            success, result = kill_process(pid)

            actions.append({


                "action": "KILL_PROCESS",
                "pid": pid,
                "name": name,
                "success": success,
                "result": result,
                "reason": alert.get("reason")

            })

    return actions

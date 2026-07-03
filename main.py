


import time

import psutil

from core.collector import get_system_info, get_processes

from core.logger import log_alerts

from core.evidence import save_evidence

from detectors.process_detector import detect as process_detect

from state import threat_stats

from config.settings import AUTO_KILL, AUTO_KILL_SCORE

from rich import print

from response.response_engine import handle_alerts


# Initialize CPU measurement
for p in psutil.process_iter():
    try:
        p.cpu_percent(None)
    except:
        pass


def main():

    print("[+] EDR Started...\n")

    while True:

        try:

            cpu, ram = get_system_info()
            processes = get_processes()

        except Exception as e:

            print(f"[bold red]ERROR Collecting Data:[/bold red] {e}")
            time.sleep(2)
            continue

        alerts = []

        try:

            alerts = process_detect(processes)

        except Exception as e:

            print(f"[bold red]ERROR In Detector:[/bold red] {e}")

        actions = handle_alerts(alerts, processes, dry_run=False)

        if actions:

            print("\n[bold red]ACTIONS TAKEN[/bold red]\n")

            for a in actions:

                print(f"[{a['action']}] PID {a.get('pid')} | " f"{a.get('name')} | " f"{a.get('result', a.get('reason'))}" )

        print("=" * 80)

        print("[bold cyan]SYSTEM MONITOR[/bold cyan]".center(80))

        print("=" * 80)

        print(f"[white]CPU: {cpu}% | RAM: {ram}%[/white]\n")

        if alerts:

            print("[bold red][ ALERTS ][/bold red]\n")

            for alert in alerts:

                level = alert.get("level", "INFO")

                if level == "CRITICAL":
                    color = "red"

                elif level == "WARNING":
                    color = "yellow"

                else:
                    color = "green"

                print(
                    f"[{color}]{level}[/] | "
                    f"PID {alert['pid']} | "
                    f"{alert['name']}"
                )

                print(
                    f"Score: {alert['score']} | "
                    f"{alert['reason']}\n"
                )

                if alert.get("score", 0) >= 7:

                    for p in processes:

                        if p["pid"] == alert["pid"]:

                            save_evidence(p)
                            break

        else:

            print("[green][ OK ] No Suspicious Activity[/green]")

        print("\n[bold magenta]TOP THREATS:[/bold magenta]")

        top = sorted(
            threat_stats.items(),
            key=lambda x: x[1]["score"],
            reverse=True
        )[:5]

        for name, data in top:

            print(
                f"[magenta]- {name} | "
                f"Score: {data['score']} | "
                f"Count: {data['count']}[/magenta]"
            )

        print("=" * 80)

        try:

            log_alerts(alerts)

        except Exception as e:

            print(f"[bold red]ERROR Logging:[/bold red] {e}")

        time.sleep(3)


if __name__ == "__main__":

    main()




import time

from core.collector import get_processes

from core.logger import log_alerts 

from detectors.process_detector import detect as process_detect

def main () :

    print(" [+] EDR Started...\n")

    while True :

        try :

            processes = get_processes()

            alerts = []
            
            alerts.extend(process_detect(processes))

            if alerts :

                for alert in alerts :

                    print(f"[{alert['level']}]" f"{alert['name']}" f"(PID : {alert['pid']}) -> " f"{alert['reason']}" f"[Score : {alert['score']} ]")

                log_alerts(alerts)

            time.sleep(2)

        except KeyboardInterrupt :

            print("\n[!] EDR Stopped.")

            break 

        except Exception as e :

            print(f" [ERROR] {e}")

            time.sleep(2)

if __name__ == "__main__" :

    main() 
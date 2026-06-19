
import json

from datetime import datetime 

def save_evidence(process) :

    try :

        evidence = {

            "time" : str(datetime.now()),
            "pid" : process.get("pid"),
            "name" : process.get("name"),
            "exe" : process.get("exe"),
            "cmdline" : process.get("cmdline"),
            "username" : process.get("username"),
            "ppid" : process.get("ppid"),
            "parent_name" : process.get("parent_name")
        }

        with open("evidence.log", "a") as f :

            f.write(json.dumps(evidence) + "\n")

    except Exception as e :

        print(f"[EVIDENCE ERROR] {e}") 


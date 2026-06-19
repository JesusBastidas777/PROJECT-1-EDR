


import json

from datetime import datetime

def log_alerts(alerts):

    for alert in alerts :

        log_entry = alert.copy()

        log_entry[ 'time' ] = str(datetime.now())

        with open( "alerts.log", "a") as f :

            f.write(json.dumps(log_entry) + "\n" )


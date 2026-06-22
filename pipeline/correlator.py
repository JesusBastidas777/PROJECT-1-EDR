



import time

from collections import defaultdict, deque

class EventCorrelator:

    def __init__(self):

        self.events = defaultdict(deque)

        self.window = 60 #seconds

        self.process_chains = defaultdict(list)

    def add_event(self, event):

        name = event.get("name","unknown")

        now = time.time()

        self.events[name].append({

        "time": now,

        "event": event

        })

        # Track process chains (simple version)

        parent = event.get("parent_name","unknown")

self.process_chains[parent].append(name)

        self._cleanup(name, now)

    def _cleanup(self, name, now):

        while self.events[name] and now -self.events[name][0]["time"] > self.window: self.events[name].popleft()


    def detect_patterns(self):

        alerts = []

        # 1. Burst detection

        for name, events in self.events.items():

            if len(events) >= 5:

                alerts.append({

                    "pid": 0,
                    "name": name,
                    "reason": "Event Burst Detected",
                    "score": 6,
                    "level": "WARNING"

                })

        #2 Chain detection (very simple heuristic)

        for parent, children in self.process_chains.items():

            if len(children) >= 3:

                alerts.append({

                "pid": 0,
                "name": parent,
                "reason": f"Process Chain Detected: {' -> '.join(children[-3:])}",
                "score": 7,
                "level": "CRITICAL"

                })

        #3 Temporal spike (global activity)

        total_events = sum(len(v) for v in self.events.values())

        if total_events >= 15:

            alerts.append({

                "pid": 0,
                "name": "SYSTEM",
                "reason": "High Activity Spike Detected",
                "score": 8,
                "level": "CRITICAL"

            })

        return alerts






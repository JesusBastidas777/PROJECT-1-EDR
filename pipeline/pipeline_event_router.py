


from pipeline.correlator import EventCorrelator

correlator = EventCorrelator()

def route(events):

    alerts = []

    for e in events:

        correlator.add_event(e)

    alerts.extend(correlator.detect_patterns())

    return alerts




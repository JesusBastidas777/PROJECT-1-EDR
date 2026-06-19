


previous_pid = set()

initialized = False 

cpu_history = {} # { pid : [cpu1, cpu2, ... ] 

first_seen = {} # { pid : timestamp }

last_seen = {} # { pid : timestamp }

threat_stats = {}

new_process_times = []

respawn_tracker = {}



import time 

from config import  ( CPU_THRESHOLD, SYSTEM_PROCESSES, SAFE_PROCESSES, NOISE_PROCESSES,  SPIKE_THRESHOLD , SHORT_LIFE_SECONDS, SUSPICIOUS_NAMES, PROCESS_BURST_THRESHOLD, PROCESS_BURST_WINDOW, RESPAWN_THRESHOLD, RESPAWN_WINDOW, SUSPICIOUS_PATHS, SUSPICIOUS_COMMANDS, SUSPICIOUS_PARENTS, KNOWN_MALICIOUS_HASHES, SUSPICIOUS_EXTENSIONS, SUSPICIOUS_USERS )

from state import ( previous_pid, initialized , cpu_history , first_seen, last_seen, threat_stats, new_process_times, respawn_tracker)

from os.path import splitext

def analyze(processes):

    global initialized 

    alerts = []

    seen_alerts = set()

   
    currents_pids = set()

    now = time.time()

    # - First ANTI-SPAM Run :
    
    if not initialized :

        for p in processes :

            pid = p['pid']

            if pid :

                previous_pid.add(pid)

                first_seen[pid] = now

        initialized = True 

        return []
    
    # - Main Analysis. 

    for p in processes :

        name = p.get('name')

        pid = p.get('pid')

        cpu = p.get('cpu_percent',0)

        if not name :

            continue

        name = name.strip().lower()

        currents_pids.add(pid)

        # - Record Times :

        if pid not in first_seen :

            first_seen[pid] = now 

        last_seen[pid] = now

        # - cpu history :

        history = cpu_history.setdefault(pid, [])

        history.append(cpu)

        if len(history) > 3 :

            history.pop(0)

        

        # -  Ignore Noise/System :

        if name in NOISE_PROCESSES or name in SYSTEM_PROCESSES :

            continue

        reasons = []

        score = 0 

        user_name = str(p.get("username", "")).lower()

        for sus_user in SUSPICIOUS_USERS :

            if sus_user in user_name :

                reasons.append(f"Privileged User: {user_name}")

                score += 2

                break 

        parent_name = str(p.get("parent_name", "")).lower()

        if parent_name in SUSPICIOUS_PARENTS :

            reasons.append(f"Spawned By: {parent_name}")

            score += 4 
        
        cmdline = " ".join(p.get("cmdline", [])).lower()
        
        for cmd in SUSPICIOUS_COMMANDS :
            
            if cmd in cmdline :
                
                reasons.append(f"Sucpicious Command: {cmd}")
                
                score += 5
                
                break


        # - New Process :

        if pid not in previous_pid :

            reasons.append( "New Process" )

            score += 2

            new_process_times.append(now)

            times = respawn_tracker.setdefault(name,[])

            times.append(now)

            respawn_tracker[name] = [

                t for t in times 

                if now - t <= RESPAWN_WINDOW
            ]

            if len(respawn_tracker[name]) >= RESPAWN_THRESHOLD :

                reasons.append("Repeated Respawn")

                score += 5 

        # - CPU Usage :

        if cpu > CPU_THRESHOLD :

            if name in SAFE_PROCESSES :

                reasons.append("High CPU (Known)")

                score += 1 

            else :

                reasons.append("High CPU (Unknown)")

                score += 3

        # - CPU Spike :

        if len(history) >= 2 :

            if history[- 1] - history[-2] > SPIKE_THRESHOLD :

                reasons.append("CPU Spike") 

                score += 2

            # - Suspicious Process Name :

        if name in SUSPICIOUS_NAMES :
            
            reasons.append("Suspicious Process")
            
            score += 4 

        exe = str(p.get('exe', '')).lower()

        extension = splitext(exe)[1]

        if extension in SUSPICIOUS_EXTENSIONS :

            reasons.append(f"Suspicious Extension: {extension}")

            score += 3 

        file_hash = p.get('hash')

        if file_hash in KNOWN_MALICIOUS_HASHES :

            reasons.append("Known Malicious Hash")

            score += 10
                    
        for path in SUSPICIOUS_PATHS :
            
            if path in exe :
                
                reasons.append("Suspicious Path")
                
                score += 4 
                
                break
    
         

        if reasons :
            
            level = "INFO"

            if score >= 7 :

                level = "CRITICAL"

            elif score >= 4 :

                level = "WARNING"

            key = (pid, tuple(reasons))

            if key not in seen_alerts :

                alerts.append({ "pid" : pid , "name" : name , "reason" : " | ".join(reasons), "score" : score, "level" : level})

                seen_alerts.add(key)

                stats = threat_stats.setdefault(name, {"count" : 0 , "score" : 0})

                stats["count"] += 1

                stats["score"] += score
        
    
    # - Behavioral Detection : Process Burst 

    new_process_times[:] = [

        t for t in new_process_times 

        if now - t <= PROCESS_BURST_WINDOW

        ]
    
    if len(new_process_times) >= PROCESS_BURST_THRESHOLD :

        alerts.append({"pid" : 0 , "name" : "Behavior Monitor", "reason" : "Mass Process Spawn Detected", "score" : 8 , "level" : "CRITICAL"})



            
    # - POST ANALYSIS (GHOSTS) :
        
    for old_pid in list(previous_pid) :
            
        if old_pid not in currents_pids and old_pid in first_seen:
                
            lifetime = now - first_seen.get(old_pid,now)
            
            if lifetime < SHORT_LIFE_SECONDS :
                
                alerts.append({ "pid" : old_pid, "name" : "Unknown" , "reason" : "Short-lived Process" , "score" : 5 , "level" : "WARNING"})
                
                cpu_history.pop( old_pid, None )
                
                first_seen.pop( old_pid , None )
                
                last_seen.pop( old_pid , None )

    # - Update State :
        
    previous_pid.clear()
        
    previous_pid.update(currents_pids)
        
    return alerts 









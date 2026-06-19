


import psutil, hashlib, os

def get_system_info() :

    cpu = psutil.cpu_percent(interval = 1)

    ram = psutil.virtual_memory().percent

    return cpu, ram

def get_file_hash(path) :

    try :

        if not path or not os.path.exists(path) :

            return None 
        
        sha256 = hashlib.sha256()

        with open(path, "rb") as f :

            for chunk in iter(lambda : f.read(4096), b"") : 

                sha256.update(chunk)

        return sha256.hexdigest()
    
    except :

        return None 

def get_processes():

    processes = []

    for p in psutil.process_iter([

        'pid',
        'name',
        'cpu_percent',
        'exe',
        'cmdline',
        'username',
        'ppid'
        
    ]) :
        
        try :

            cpu = p.cpu_percent(interval = None)

            parent_name = "Unknown"

            try :
                
                parent = psutil.Process(p.info['ppid'])
                
                parent_name = parent.name().lower()

            except :

                pass

            file_hash = get_file_hash(p.info['exe'])

            
            processes.append({
                "pid" : p.pid,
                "name" : p.info['name'],
                "cpu_percent" : cpu,
                "exe" : p.info['exe'],
                "cmdline" : p.info['cmdline'],
                "username" : p.info['username'],
                "ppid" : p.info['ppid'],
                "parent_name" : parent_name,
                "hash" : file_hash
                })
            
        except(psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) :

            continue
    
    return processes






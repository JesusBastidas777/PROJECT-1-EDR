import psutil

from config import PROTECTED_PROCESSES

def terminate_process(pid) :

    try :

        process = psutil.Process(pid)

        name = process.name().lower()

        if name in PROTECTED_PROCESSES :

            return False, "Protected Process"
        
        process.terminate()

        return True, name 
    
    except Exception as e :

        return False, str(e)
    

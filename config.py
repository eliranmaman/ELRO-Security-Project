from DBAgent.sqlalchemy import SQLAlchemy

debug = True
if debug:
    server = {
        "address": "",
        "port": 80
    }
else:
    server = {
        "address": "193.106.55.115",
        "port": 80
    }
log_dict = "logs/"
controller = None
db = SQLAlchemy("postgres", "qwerty", "localhost", "5432", "elro_sec")
db.connect()
data_path = "Knowledge_Base"
config_path = "{}/config".format(data_path)
cookies_map = dict()
brute_force_map = dict()
BOT_KEY = "f0ec0b2f185b868ac2f20988011328ec"
BOTS_URL = "https://api.whatismybrowser.com/api/v2/"
PROXY_DETECTOR_KEY = "4s1v32-419650-3730en-030383"
PROXY_DETECTOR_KEY_URL = "http://proxycheck.io/v2/"

bit_map = {
    "__detect_inline_scripts": 1,
    "__detect_script_files": 2,
    "__access_cookies": 4,
    "__iframe": 8,
    "__detect_csrf_requests": 16,
}

bit_map_errors = {
    1: "This site is using inline scripts",
    2: "This site is loading JavaScript files",
    4: "This site attempt to access your cookies",
    8: "This site attempt to load IFRAME (another website) in your browser",
    16: "This site attempt to invoke Cross Site Requests (CSRF)",
}

url_regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s(" \
            ")<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

enc_list = ["content", "headers", "cookies"]
enc_key = b'&E)H@McQeThWmZq4t7w!z%C*F-JaNdRg'

blocked_url = "elro-sec.com"
blocked_path = "/blocked.html"

log_format = "{}"
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
db = None
data_path = "Data/"
cookies_map = dict()
brute_force_map = dict()
BOT_KEY = "f0ec0b2f185b868ac2f20988011328ec"
BOTS_URL = "https://api.whatismybrowser.com/api/v2/"
PROXY_DETECTOR_KEY = "4s1v32-419650-3730en-030383"
PROXY_DETECTOR_KEY_URL = "http://proxycheck.io/v2/"
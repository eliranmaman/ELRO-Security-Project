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

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
controller = None
db = SQLAlchemy("postgres", "qwerty", "localhost", "5432", "elro_sec")
db.connect()
data_path = "../Knowledge_Base"
config_path = "{}/config".format(data_path)
detectors_config_path = "{}/detectors".format(config_path)
controller_config_path = "{}/controllers".format(config_path)
cookies_map = dict()
brute_force_map = dict()


url_regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

enc_list = ["content", "headers", "cookies"]
enc_key = b'&E)H@McQeThWmZq4t7w!z%C*F-JaNdRg'
authorized_servers = ["77.137.114.12", "176.230.79.33"]
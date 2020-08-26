from DBAgent.sqlalchemy import SQLAlchemy

db = SQLAlchemy("postgres", "qwerty", "localhost", "5432", "elro_sec")
db.connect()
data_path = "Knowledge_Base"
config_path = "{}/config".format(data_path)
detectors_config_path = "{}/detectors".format(config_path)
controller_config_path = "{}/controllers".format(config_path)


url_regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

authorized_servers = ["54.162.177.227"]
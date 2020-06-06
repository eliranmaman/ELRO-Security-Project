import json
import re
from config import data_path


class SQLValidator(object):
    __Forbidden_FILE = data_path+"/Detectors/SQLValidator/forbidden.json"

    def __init__(self):
        self.__regex_list = list()
        self.__load_data()

    def validate(self, content):
        content = str(content).upper()
        threats_count = 0
        for regex_dict in self.__regex_list:
            matches = re.findall(regex_dict["phrase"], content)
            print(matches)
            print(regex_dict["value"])
            if len(matches) > 0:
                threats_count += regex_dict["value"]
        return threats_count

    def __load_data(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            self.__regex_list = data['regex_list']


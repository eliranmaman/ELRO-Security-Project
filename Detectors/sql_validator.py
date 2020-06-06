import json
import re
from config import data_path


class SQLValidator(object):
    __Forbidden_FILE = data_path+"/Detectors/SQLValidator/forbidden.json"
    """"this class will validate as a second layer of defense 
        if the given content contains sql injection payload of not
        :param content - the request/response content to validate,
        :param forbidden - addition regex list to block with
        :param legitimate - regex list of phrases that the client allow
        :return: double number - the percentage of sql injection certainty """
    def __init__(self):
        self.__regex_list = list()
        self.__load_data()

    def validate(self, content, forbidden=None, legitimate=None):
        content = str(content).upper()
        threats_count = 0

        if legitimate is not None:
            self.__regex_list -= legitimate

        for regex_dict in self.__regex_list:
            matches = re.findall(regex_dict["phrase"], content)
            if len(matches) > 0:
                threats_count += regex_dict["value"]
        return threats_count

    def __load_data(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            self.__regex_list = data['regex_list']


import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class XMLDetector(Detector):
    """this class will detect XML injections attempts in a given parsed request/response"""
    __Forbidden_FILE = data_path+"/Detectors/XMLInjection/forbidden.json"

    # TODO: adjust usage with legitimate and forbidden list - will we receive regex ?
    #  or only words? (especially in the legit list) - need to think on solution
    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.__flag = list()
        self.refresh()
        self.name = "xml_detector"

    # if detected an attack attempt this method will return True and False otherwise
    def detect(self, parsed_data, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        Just to be clear: there is not absolute way to determine if request arrive from legit user or not.
        We can just look for the "sloppy" guys, by checking the User-Agent.
        This method will determine if the request arrive from bot or not.
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: list of additional malicious words/regex that we wish to add to the forbidden list on runtime
        :param legitimate: The legitimate words/regex that we need automatically approve
        :return: boolean
        """
        parsed_data = str(parsed_data)
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        for malicious_phrase in self.__forbidden:
            matches = re.findall(malicious_phrase, parsed_data)
            if len(matches) > 0:
                return True
        return False

    # returns the forbidden list
    def get_forbidden_list(self):
        return self.__forbidden

    # loads the external data
    def refresh(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            for i in data['forbidden']:
                self.__forbidden.append(i)
            for i in data['dangerous']:
                self.__flag.append(i)
        data_file.close()

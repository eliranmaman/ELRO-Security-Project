import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class XMLDetector(Detector):
    """this class will detect XML injections attempts"""
    __Forbidden_FILE = data_path+"/Detectors/XMLInjection/forbidden.json"

    # TODO: adjust usage with legitimate and forbidden list - will we receive regex ?
    #  or only words? (especially in the legit list) - need to think on solution
    def __init__(self):
        self.__forbidden = list()
        self.__flag = list()
        self.refresh()

    # if detected an attack attempt this method will return True and False otherwise
    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        request = str(request)
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        for malicious_phrase in self.__forbidden:
            matches = re.findall(malicious_phrase, request)
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

import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class XSSDetector(Detector):
    """this class will detect XSS injections attempts"""
    __Forbidden_FILE = data_path+"/Detectors/XSSInjection/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.refresh()

    # if detected an attack attempt this method will return True and False otherwise
    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        request = str(request).upper()
        forbidden_word_list = []
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        # check for xss injection attempts
        for forbidden_word in self.__forbidden:
            try:
                forbidden_words = re.findall(forbidden_word, request)
            except Exception as e:
                print("Exception with " + forbidden_word)
            if len(forbidden_words) > 0:
                forbidden_word_list.append(forbidden_words)
        # if detected a forbidden word it is probably an attack
        if len(forbidden_word_list) > 0:
            return True
        return False

    # returns the forbidden list
    def get_forbidden_list(self):
        return self.__forbidden

    # loads the external data
    def refresh(self):
        try:
            with open(self.__Forbidden_FILE, "r", encoding="utf-8") as data_file:
                data = json.load(data_file)
                for i in data['forbidden']:
                    self.__forbidden.append(i)
            data_file.close()
        except Exception as e:
            print(e)


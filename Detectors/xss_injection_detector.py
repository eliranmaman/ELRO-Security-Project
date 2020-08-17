import json

from DBAgent.orm import to_json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class XSSDetector(Detector):
    """this class will detect XSS injections attempts in a given parsed request/response"""
    __Forbidden_FILE = data_path+"/Detectors/XSSInjection/forbidden.json"

    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.refresh()
        self.name = "xss_detector"

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
        parsed_data_copy = parsed_data  # Copy the parsed data to avoid change the origin
        parsed_data_copy.headers = to_json(parsed_data_copy.headers)
        parsed_data_copy = str(to_json(parsed_data_copy)).upper()
        forbidden_word_list = []
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        # check for xss injection attempts
        for forbidden_word in self.__forbidden:
            try:
                forbidden_words = re.findall(forbidden_word, parsed_data_copy)
                if len(forbidden_words) > 0:
                    forbidden_word_list.append(forbidden_words)
            except Exception as e:
                print("Exception with " + forbidden_word)
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


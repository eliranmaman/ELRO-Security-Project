import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class SqlInjection(Detector):
    """this class will detect SQL injections attempts in a given parsed request/response"""
    __Forbidden_FILE = data_path+"/Detectors/SQLInjection/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.__break_characters = list()
        self.refresh()

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
        parsed_data = str(parsed_data).upper()
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden -= legitimate
            self.__break_characters -= legitimate
        context_break_list = []
        forbidden_word_list = []
        # check for context break intentions
        for break_char in self.__break_characters:
            context_breaks = re.findall(break_char, parsed_data)
            if len(context_breaks) > 0:
                context_break_list.append(context_breaks)
                if sensitivity == Sensitivity.Sensitive:
                    return True
        # check for forbidden words
        for forbidden_word in self.__forbidden:
            forbidden_words = re.findall(forbidden_word, parsed_data)
            if len(forbidden_words) > 0:
                forbidden_word_list.append(forbidden_words)
        # if tries to break context with forbidden words it is probably an attack
        if len(context_break_list) > 0 and len(forbidden_word_list) > 0:
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
            for i in data['break_characters']:
                self.__break_characters.append(i)
        data_file.close()

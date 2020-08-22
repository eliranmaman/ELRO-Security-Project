import json
import logging

from DBAgent.orm import to_json
from Detectors import Detector, Sensitivity
from config import data_path, log_dict
import re


def create_content_as_str(content):
    my_str = ""
    for item, val in content.__dict__.items():
        my_str += "{}:{} ".format(item, val)
    return my_str.upper()


class SqlInjection(Detector):
    """ this class will detect SQL injections attempts in a given parsed request/response """
    __Forbidden_FILE = data_path+"/Detectors/SQLInjection/forbidden.json"
    __Validation_FILE = data_path+"/Detectors/SQLInjection/validation.json"
    __SQL_THRESHOLD = 0.5

    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.__break_characters = list()
        self.refresh()
        self.name = "sql_detector"

    def detect(self, parsed_data, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
         This method will detect an SQL attack attempt by the regex and data given in the 'SQLInjection' folder under
         'Data' folder.
         :param parsed_data: Parsed Data (from the parser module) of the request / response
         :param sensitivity: The sensitivity of the detection
         :param forbidden: list of additional malicious words/regex that we wish to add to the forbidden list on runtime
         :param legitimate: The legitimate words/regex that we need to automatically approve
         :return: boolean

        """
        parsed_headers_as_str = create_content_as_str(parsed_data.headers)  # Copy the parsed data to avoid change the origin
        # check for context break intentions in the headers first
        for break_char in self.__break_characters:
            context_breaks = re.findall(break_char, parsed_headers_as_str)
            if len(context_breaks) > 0:
                final_decision_assurance = self.final_validation(parsed_data)
                return True if final_decision_assurance >= self.__SQL_THRESHOLD else False
        # if no context breaks were found continue to check the request
        parsed_data_as_str = create_content_as_str(parsed_data)
        print(parsed_data_as_str)
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
                print("Found Threat of SQL INJECTION ATTACK, "
                            "CONTEXT BREAK CHAR: " + break_char + " was found in: " + parsed_data)
                context_break_list.append(context_breaks)

        # check for forbidden words
        for forbidden_word in self.__forbidden:
            forbidden_words = re.findall(forbidden_word, parsed_data)
            if len(forbidden_words) > 0:
                print("Found Threat of SQL INJECTION ATTACK, "
                            "Forbidden word: " + forbidden_word + " was found in: " + parsed_data)
                forbidden_word_list.append(forbidden_words)

        # if tries to break context with forbidden words it is probably an attack
        if len(context_break_list) > 0 and len(forbidden_word_list) > 0:
            final_decision_assurance = self.final_validation(parsed_data)
            return True if final_decision_assurance >= self.__SQL_THRESHOLD else False
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

    def final_validation(self, content, legitimate=None):
        """
        this method will validate if the given content
        contains sql injection payload of not as a second layer of defense
        :param content - the request/response content to validate,
        :param legitimate - regex list of phrases that the client allow
        :return: double number - the percentage of sql injection certainty
        """
        with open(self.__Validation_FILE, "r") as data_file:
            data = json.load(data_file)
            regex_list = data['regex_list']
            content = str(content).upper()
            threats_count = 0

            if legitimate is not None:
                regex_list -= legitimate

            for regex_dict in regex_list:
                matches = re.findall(regex_dict["phrase"], content)
                if len(matches) > 0:
                    threats_count += regex_dict["value"]
            return threats_count



import json
import re

from Detectors import Detector
from Knowledge_Base import Sensitivity, create_content_as_str


class XSSDetector(Detector):
    """this class will detect XSS injections attempts in a given parsed request/response"""

    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.refresh()

    def detect(self, parsed_data, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        This method will detect an XML attack attempt by the regex and data given in the 'XSSInjection' folder
        under 'Data' folder..
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detection
        :param forbidden: list of additional malicious words/regex that we wish to add to the forbidden list on runtime
        :param legitimate: The legitimate words/regex that we need automatically approve
        :return: boolean
        """
        parsed_data_as_str = create_content_as_str(parsed_data.headers)  # Copy the parsed data to avoid change the origin
        parsed_data_as_str += create_content_as_str(parsed_data)
        # logger.info("xss_injection got parsed_data ::--> " + parsed_data)
        forbidden_word_list = []
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        # check for xss injection attempts
        for forbidden_word in self.__forbidden:
            try:
                forbidden_words = re.findall(forbidden_word, parsed_data)
                if len(forbidden_words) > 0:
                    # logger.info("Found Threat of XSS ATTACK, Forbidden regex: " + forbidden_word + " was found in: " + parsed_data)
                    forbidden_word_list.append(forbidden_words)
            except Exception as e:
                pass
        # if detected a forbidden word it is probably an attack
        if len(forbidden_word_list) > 0:
            return True
        return False

    # returns the forbidden list
    def get_forbidden_list(self):
        return self.__forbidden

    # loads the external data
    def refresh(self):
        """
        Make an union of the list lists, (refreshing the data)
        This be done efficiently by using both the set() and union() function.
        This also takes care of the repetition and prevents them.
        :return: None
        """
        self.__forbidden = list(set(self.__forbidden) | set(self.kb["forbidden"]))


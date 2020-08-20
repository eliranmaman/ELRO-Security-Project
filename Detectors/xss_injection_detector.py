import json
import sys

from Detectors import Detector, Sensitivity
from config import data_path, log_dict
import re
import logging

sys.stderr = open(log_dict + "/xss_injection.log", 'a+')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)


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
        This method will detect an XML attack attempt by the regex and data given in the 'XSSInjection' folder
        under 'Data' folder..
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detection
        :param forbidden: list of additional malicious words/regex that we wish to add to the forbidden list on runtime
        :param legitimate: The legitimate words/regex that we need automatically approve
        :return: boolean
        """
        parsed_data = str(parsed_data).upper()
        logger.info("xss_injection got parsed_data ::--> " + parsed_data)
        forbidden_word_list = []
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        # check for xss injection attempts
        for forbidden_word in self.__forbidden:
            try:
                forbidden_words = re.findall(forbidden_word, parsed_data)
            except Exception as e:
                logger.exception("Exception with " + forbidden_word)
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
            logger.exception(e)


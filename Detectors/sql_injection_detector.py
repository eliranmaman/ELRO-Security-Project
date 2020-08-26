import json
import re

from Detectors import Detector
from Knowledge_Base import Sensitivity, create_content_as_str


class SqlInjection(Detector):
    """ this class will detect SQL injections attempts in a given parsed request/response """

    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.__break_characters = list()
        self.refresh()

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

        # check the query string first (url params)
        query_string = parsed_data.headers.__dict__['environ']['QUERY_STRING']
        for break_char in self.__break_characters:
            context_breaks = re.findall(break_char, query_string)
            if len(context_breaks) > 0:
                print("INSIDE LEN > 0")
                final_decision_assurance = self.final_validation(query_string, Sensitivity.VerySensitive)
                return True if final_decision_assurance >= self.kb["threshold"] else False

        # if no context breaks were found continue to check the request
        parsed_data_as_str = create_content_as_str(parsed_data) # Copy the parsed data to avoid change the origin
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden -= legitimate
            self.__break_characters -= legitimate
        context_break_list = []
        forbidden_word_list = []

        # check for context break intentions in the request itself
        for break_char in self.__break_characters:
            context_breaks = re.findall(break_char, parsed_data_as_str)
            if len(context_breaks) > 0:
                # logger.info("Found Threat of SQL INJECTION ATTACK, "
                #             "CONTEXT BREAK CHAR: " + break_char + " was found in: " + parsed_data)
                context_break_list.append(context_breaks)
                if sensitivity == Sensitivity.Sensitive:
                    final_decision_assurance = self.final_validation(parsed_data_as_str)
                    return True if final_decision_assurance >= self.kb["threshold"] else False

        # check for forbidden words
        for forbidden_word in self.__forbidden:
            forbidden_words = re.findall(forbidden_word, parsed_data_as_str)
            if len(forbidden_words) > 0:
                # logger.info("Found Threat of SQL INJECTION ATTACK, "
                #             "Forbidden word: " + forbidden_word + " was found in: " + parsed_data)
                forbidden_word_list.append(forbidden_words)

        # if tries to break context with forbidden words it is probably an attack
        if len(context_break_list) > 0 and len(forbidden_word_list) > 0:
            final_decision_assurance = self.final_validation(parsed_data_as_str)
            return True if final_decision_assurance >= self.kb["threshold"] else False
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
        self.__break_characters = list(set(self.__break_characters) | set(self.kb["break_characters"]))

    def final_validation(self, content, sensitivity=Sensitivity.Regular, legitimate=None):
        """
        this method will validate if the given content
        contains sql injection payload of not as a second layer of defense
        :param content - the request/response content to validate,
        :param sensitivity - the sensitivity of the validation
        :param legitimate - regex list of phrases that the client allow
        :return: double number - the percentage of sql injection certainty
        """
        regex_list = self.kb['regex_list']
        content = content.upper() if type(content) is str else str(content).upper()
        threats_count = 0

        if legitimate is not None:
            regex_list -= legitimate

        for regex_dict in regex_list:
            matches = re.findall(regex_dict["phrase"], content)
            if len(matches) > 0:
                # logger.info("SQL VALIDATOR FOUND: " + " ".join([str(m) for m in matches]))
                threats_count += regex_dict["value"]

        if sensitivity is Sensitivity.VerySensitive:
            threats_count = 2*threats_count
        return threats_count



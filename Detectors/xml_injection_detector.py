import re

from Detectors import Detector
from Knowledge_Base import Sensitivity, create_content_as_str


class XMLDetector(Detector):
    """this class will detect XML injections attempts in a given parsed request/response"""

    # TODO: adjust usage with legitimate and forbidden list - will we receive regex ?
    #  or only words? (especially in the legit list) - need to think on solution
    def __init__(self):
        super().__init__()
        self.__forbidden = list()
        self.__flag = list()
        self.refresh()

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
        parsed_data_as_str = create_content_as_str(parsed_data.headers)  # Copy the parsed data to avoid change the origin
        parsed_data_as_str += create_content_as_str(parsed_data)
        # logger.info("xml_injection got parsed_data ::--> " + parsed_data)
        if forbidden is not None:
            self.__forbidden += forbidden
        if legitimate is not None:
            self.__forbidden = list(filter(lambda x: x not in legitimate, self.__forbidden))
        for malicious_phrase in self.__forbidden:
            matches = re.findall(malicious_phrase, parsed_data_as_str)
            if len(matches) > 0:
                # logger.info("Found Threat of XML ATTACK, Forbidden regex: " + malicious_phrase + " was found in: "
                #             + parsed_data)
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
        self.__flag = list(set(self.__flag) | set(self.kb["dangerous"]))

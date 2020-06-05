import time
import requests
import json

from Detectors import Detector, Sensitivity, Classification
from config import BOT_KEY, BOTS_URL


class Bots(Detector):

    def __init__(self):
        super().__init__()
        self._bots_url = "{}/user_agent_parse".format(BOTS_URL)
        self._bots_header = {"X-API-KEY": BOT_KEY}
        self._bots_data = {"parse_options": {}}

    def detect(self, request, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        Just to be clear: there is not absolute way to determine if request arrive from legit user or not.
        We can just look for the "sloppy" guys, by checking the User-Agent.
        This method will determine if the request arrive from bot or not.
        :param request: send the full request object.
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: list of paths to protect
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # Pre Processing
        check_pre_processing = self._pre_processing(forbidden, legitimate, request)
        if check_pre_processing == Classification.Clean:
            return False
        # ------ This code will run if the path is in the forbidden list ------ #
        user_agent = request.headers.get('User-Agent', None)
        if user_agent is None:
            return True
        self._bots_data["user_agent"] = user_agent
        user_agent_data = self.__parse_bots_data()
        is_detected = False
        print(user_agent_data)
        # Start Check by the web sensitivity #
        # ----- Regular ----- #
        is_detected = is_detected or user_agent_data["is_restricted"] or  user_agent_data["is_abusive"]
        if sensitivity == Sensitivity.Regular or is_detected:
            return is_detected
        # ----- Sensitive  ----- #
        is_detected = is_detected or user_agent_data["is_spam"] or user_agent_data["is_weird"]
        if sensitivity == Sensitivity.Sensitive or is_detected:
            return is_detected
        # ----- Very Sensitive ----- #
        is_detected = is_detected or user_agent_data["software_type"] in self._forbidden
        if is_detected:  # Will save the computing time if its already true
            return True
        is_detected = is_detected or user_agent_data["hardware_type"] in self._forbidden
        return is_detected

    def __parse_bots_data(self):
        """
        This method will send request true API to get more information about the specific User-Agent
        than parse the information and return it.
        :return: dict
        """
        bots_response = requests.post(self._bots_url, data=json.dumps(self._bots_data), headers=self._bots_header)
        # ---- Check that the request is succeed ---- #
        if bots_response.status_code != 200:
            return Classification.NoConclusion
        elif type(bots_response.json()) is str:
            bots_response = json.loads(bots_response.json())
        else:
            bots_response = bots_response.json()
        if "parse" not in bots_response:
            return Classification.NoConclusion
        # ---- Parse the information ---- #
        bots_response = bots_response["parse"]
        return {
            "software_type": bots_response.get("software_type", None),
            "hardware_type": bots_response.get("hardware_type", None),
            "is_weird": bots_response.get("is_weird", False),
            "is_restricted": bots_response.get("is_restricted", False),
            "is_spam": bots_response.get("is_spam", False),
            "is_abusive": bots_response.get("is_abusive", False)
        }

    def _is_legitimate(self, legitimate, request):
        """
        This method is work on path access only.
        :param legitimate: list of legitimate path, that bots are allowed to visit.
        :param request: the original request.
        :return: Classification Enum
        """
        # Cleaning the request path
        req_path = str(request.path).strip("/")
        for path in legitimate:
            if req_path in path:
                return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None





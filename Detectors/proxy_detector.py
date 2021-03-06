import requests
import json

from Detectors import Detector
from Knowledge_Base import Sensitivity, Classification


class ProxyDetector(Detector):

    def __init__(self):
        super().__init__()
        self._proxy_url = self.kb["PROXY_DETECTOR_KEY_URL"]

    def detect(self, parsed_data, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        This method will try to detect parsed_data that arrive from proxies, with pre defined list & updated API that
        contains list of proxies.
        :param parsed_data: send the full HttpRequest object.
        :param sensitivity: The sensitivity of the detection
        :param forbidden: list of paths to protect
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # Pre Processing
        check_pre_processing = self._pre_processing(forbidden, legitimate, parsed_data)
        if check_pre_processing == Classification.Clean:
            return False
        elif check_pre_processing == Classification.Detected:
            return True
        # ------ Start Detecting ------ #
        client_ip = parsed_data.from_ip
        ip_data = self.__parse_ip_data(client_ip)
        if ip_data == Classification.Detected:
            return True
        return False

    def __parse_ip_data(self, ip):
        """
        This method will send request through API to get more information about the specific User-Agent
        than parse the information and return it.
        :return: dict
        """
        ip_url = self.kb["PROXY_DETECTOR_FORMAT"].format(self._proxy_url, ip, self.kb["PROXY_DETECTOR_KEY"])
        proxy_detector_response = requests.get(ip_url)
        # ---- Check that the request is succeed ---- #
        if proxy_detector_response.status_code != 200:
            return Classification.NoConclusion
        elif type(proxy_detector_response.json()) is str:
            proxy_detector_response = json.loads(proxy_detector_response.json())
        else:
            proxy_detector_response = proxy_detector_response.json()
        if "status" not in proxy_detector_response:
            return Classification.NoConclusion
        elif proxy_detector_response["status"] != self.kb["OK_STATUS"]:
            return Classification.NoConclusion
        elif ip not in proxy_detector_response:
            return Classification.NoConclusion
        proxy_detector_response = proxy_detector_response[ip]
        if "proxy" not in proxy_detector_response:
            return Classification.NoConclusion
        return Classification.Detected if proxy_detector_response["proxy"] == self.kb["YES_STATUS"] else Classification.Clean

    def _is_legitimate(self, legitimate, parsed_data):
        """
        This method is work on path access only.
        :param legitimate: list of legitimate ips, that are classified as Clean.
        :param parsed_data: the original HttpRequest.
        :return: Classification Enum
        """
        # Cleaning the request path
        client_ip = parsed_data.from_ip
        if client_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def _is_forbidden(self, forbidden, parsed_data):
        """
        This method is work on path access only.
        :param forbidden: list of forbidden ips, that are classified as proxy.
        :param parsed_data: the original HttpRequest.
        :return: Classification Enum
        """
        # Cleaning the request path
        client_ip = parsed_data.from_ip
        if client_ip in forbidden:
            return Classification.Detected
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None





import time
import requests
import json

from Detectors import Detector, Sensitivity, Classification
from config import PROXY_DETECTOR_KEY_URL, PROXY_DETECTOR_KEY

# TODO: tests


class ProxyDetector(Detector):

    def __init__(self):
        super().__init__()
        self._proxy_url = PROXY_DETECTOR_KEY_URL

    def detect(self, request, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        This method will try to detect requests that arrive from proxies, with pre define list & updated API that
        contains list of proxies.
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
        elif check_pre_processing == Classification.Detected:
            return True
        # ------ Start Detecting ------ #
        client_ip = request.client_address[0]
        ip_data = self.__parse_ip_data(client_ip)
        if ip_data == Classification.Detected:
            return True
        return False

    def __parse_ip_data(self, ip):
        """
        This method will send request true API to get more information about the specific User-Agent
        than parse the information and return it.
        :return: dict
        """
        ip_url = "{}{}?key={}".format(self._proxy_url, ip, PROXY_DETECTOR_KEY)
        proxy_detector_response = requests.get(ip_url)
        # ---- Check that the request is succeed ---- #
        if proxy_detector_response.status_code != 200:
            return Classification.NoConclusion
        elif type(proxy_detector_response.json()) is str:
            proxy_detector_response = json.loads(proxy_detector_response.json())
        else:
            proxy_detector_response = proxy_detector_response.json()
        print(proxy_detector_response)
        if "status" not in proxy_detector_response:
            return Classification.NoConclusion
        elif proxy_detector_response["status"] != "ok":
            return Classification.NoConclusion
        elif ip not in proxy_detector_response:
            return Classification.NoConclusion
        proxy_detector_response = proxy_detector_response[ip]
        if "proxy" not in proxy_detector_response:
            return Classification.NoConclusion
        return Classification.Detected if proxy_detector_response["proxy"] == "yes" else Classification.Clean

    def _is_legitimate(self, legitimate, request):
        """
        This method is work on path access only.
        :param legitimate: list of legitimate ips, that are classified as Clean.
        :param request: the original request.
        :return: Classification Enum
        """
        # Cleaning the request path
        client_ip = request.client_address[0]
        if client_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def _is_forbidden(self, forbidden, request):
        """
        This method is work on path access only.
        :param forbidden: list of forbidden ips, that are classified as proxy.
        :param request: the original request.
        :return: Classification Enum
        """
        # Cleaning the request path
        client_ip = request.client_address[0]
        if client_ip in forbidden:
            return Classification.Detected
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None





import re

from DBAgent import CookiesToken
from Detectors import Detector, Sensitivity, Classification
from Detectors.detectors_config import token_regex
from config import db


class CookiesPoisoning(Detector):

    def __init__(self):
        super().__init__()
        self.name = "cookie_poisoning_detector"

    def detect(self, parsed_data, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: The path's that forbidden in any case for cross-site (list)
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # Pre Processing
        check_pre_processing = self._pre_processing(forbidden, legitimate, parsed_data)
        if check_pre_processing == Classification.Detected:
            return True
        elif check_pre_processing == Classification.Clean:
            return False
        # Getting the request Cookies (e.g same-origin)
        return self._check_cookie_is_authorized(parsed_data)

    def _check_cookie_is_authorized(self, parsed_data):
        """
        To do (Generate the key in the proxy for verifying)
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :return:
        """
        cookies = parsed_data.headers.get("Cookie", None)
        print(cookies)
        if cookies is None:
            return False
        cookies_token = db.get_session().query(CookiesToken).\
            filter_by(active=True, ip=parsed_data.from_ip, dns_name=parsed_data.host_name).first()
        if cookies_token is None:
            return False
        m = re.match(token_regex, cookies)
        if m is None:
            return True
        secret_value = m.group(1)
        check = secret_value != cookies_token.token
        return check

    def _is_legitimate(self, legitimate, parsed_data):
        """
        The method works on IP access control, there is legit ips that allowed to
        access without token.
        :param legitimate: list of ips
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :return: Classification Enum
        """
        req_ip = parsed_data.from_ip
        if req_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None

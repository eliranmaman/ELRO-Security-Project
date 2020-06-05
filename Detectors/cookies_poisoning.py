import re

from Detectors import Detector, Sensitivity, Classification
from config import cookies_map

# TODO: implement the is_legitimate & is_forbidden

class CookiesPoisoning(Detector):

    def generate_key(self, client_addr, url):
        return "{}<=>{}".format(client_addr, url).lower()

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        :param request: send the full request object.
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: The path's that forbidden in any case for cross-site (list)
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # Pre Processing
        check_pre_processing = self._pre_processing(forbidden, legitimate, request)
        if check_pre_processing == Classification.Detected:
            return True
        elif check_pre_processing == Classification.Clean:
            return False
        # Getting the request Cookies (e.g same-origin)
        return self._check_cookie_is_authorized(request)

    def _check_cookie_is_authorized(self, request):
        """
        To do (Generate the key in the proxy for verifying)
        :param cookies:
        :param request:
        :return:
        """
        cookies = request.headers.get('Cookie', None)
        if cookies is None:
            return False
        m = re.match(".*?Elro-Sec-Token=.*\"(.*?)@Elro-Sec-End", cookies)
        if m is None:
            return True
        secret_value = m.group(1)
        key = self.generate_key(request.client_address[0], request.headers.get('Host', "elro-sec.com"))
        check = cookies_map.get(key, None) != "{}@Elro-Sec-End".format(secret_value) # TODO: thsi is not readable.
        return check

    def _is_legitimate(self, legitimate, request):
        """
        The method works on IP access control, there is legit ips that allowed to
        access without token.
        :param legitimate: list of ips
        :param request: The original request
        :return: Classification Enum
        """
        req_ip = str(request.client_address[0])
        if req_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None

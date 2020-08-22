from urllib.parse import urlparse

from Detectors import Detector
from Knowledge_Base import Sensitivity, Classification


class CSRF(Detector):

    def __init__(self):
        super().__init__()

    def detect(self, parsed_data, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detection
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
        # Getting the request Type (e.g same-origin)
        sec_fetch_site = parsed_data.headers.get(self.kb["relevant_header"], None)
        referer = parsed_data.headers.get("Referer", None)
        referer = urlparse(referer) if referer is not None else referer
        referer = '{uri.netloc}'.format(uri=referer) if referer is not None else referer
        # If the request is in the same-origin return False
        if sec_fetch_site == self.kb["same_origin"] and sec_fetch_site is not None:
            return False
        if referer != parsed_data.host_name and not None:
            return False
        # Sensitivity policy
        method = parsed_data.method
        if sensitivity == Sensitivity.Regular:
            if method in self.kb["sensitivity"][str(Sensitivity.Regular.value)]:
                return True
        elif sensitivity == Sensitivity.Sensitive:
            if method not in self.kb["sensitivity"][str(Sensitivity.Sensitive.value)]:
                return True
        else:  # Sensitivity.VerySensitive
            return True
        return False

    def _is_legitimate(self, legitimate, parsed_data):
        """
        The method works on path access control, there is legit path that allowed to
        access with CSRF request.
        :param legitimate: list of path
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :return: Classification Enum
        """
        # Cleaning the request path
        req_path = parsed_data.path.strip("/")
        for path in legitimate:
            if req_path in path:
                return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None

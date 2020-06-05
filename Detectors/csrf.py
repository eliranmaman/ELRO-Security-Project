from Detectors import Detector, Sensitivity, Classification

# TODO: tests


class CSRF(Detector):

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
        # Getting the request Type (e.g same-origin)
        sec_fetch_site = request.headers.get('Sec-Fetch-Site', None)
        # If the request is in the same-origin return False
        if sec_fetch_site == "same-origin":  # TODO: check if the attacker can change this header
            return False
        # Sensitivity policy
        method = str(request.method).upper()
        if sensitivity == Sensitivity.Regular:
            if method == "POST" or method == "DELETE" or method == "PUT":
                return True
        elif sensitivity == Sensitivity.Sensitive:
            if method != "GET":
                return True
        else:  # Sensitivity.VerySensitive
            return True
        return False

    def _is_legitimate(self, legitimate, request):
        """
        The method works on path access control, there is legit path that allowed to
        access with CSRF request.
        :param legitimate: list of path
        :param request: The original request
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

from Detectors import Detector, Sensitivity


class CSRF(Detector):

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        :param request: send the full request object.
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: The path's that forbidden in any case for cross-site (list)
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # Setting the forbidden list
        if forbidden is None:
            forbidden = list()
        forbidden += self.get_forbidden_list()
        # Setting the legitimate list
        if legitimate is None:
            legitimate = list()
        # Cleaning the request path
        req_path = str(request.path).strip("/")
        # Checking if the path is in the forbidden list of the server.
        for path in forbidden:
            if path in request.path:
                return False
        # Checking if the path is in the legitimate list of the server.
        for path in legitimate:
            if path == req_path:
                return True
        # Getting the request Type (e.g same-origin)
        sec_fetch_site = request.headers.get('Sec-Fetch-Site', None)
        # If the request is in the same-origin return False
        if sec_fetch_site == "same-origin":
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

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        return None

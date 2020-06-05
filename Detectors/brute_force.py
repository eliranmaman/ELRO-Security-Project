import time

from Detectors import Detector, Sensitivity, Classification
from config import brute_force_map as map


# TODO: change brute_force_map to come from database
# TODO: tests

class BruteForce(Detector):

    def __init__(self):
        super().__init__()
        self._data_map = map

    def detect(self, request, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        The method will check path that are in the forbidden list, for every path in this list
        the method will perform brute force check by number of request in the last 1min.
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
        # ------ This code will run if the path is in the forbidden list ------ #
        req_path = str(request.path).strip("/")
        client_ip = request.client_address[0]
        last_request, counter = self._get_previous_request_info(client_ip, req_path)
        # Sensitivity will determinate the max_counter.
        if sensitivity == Sensitivity.Regular:
            max_counter = 10  # TODO: discuss about the const numbers.
        elif sensitivity == Sensitivity.Sensitive:
            max_counter = 5
        elif sensitivity == Sensitivity.VerySensitive:
            max_counter = 3
        else:
            max_counter = 3
        # Check if the last request was more that 1min ago
        if time.time() - last_request > 60:  # TODO: discuss about the const 1min.
            self._data_map[client_ip][req_path] = (time.time(), 1)
            return False
        elif counter >= max_counter:
            self._data_map[client_ip][req_path] = (time.time(), counter + 1)
            return True
        # --- The counter is < max_counter --- #
        self._data_map[client_ip][req_path] = (time.time(), counter + 1)
        return False

    def _get_previous_request_info(self, ip, path):
        if ip not in self._data_map:
            return time.time(), 0
        elif path not in self._data_map[ip]:
            return time.time(), 0
        else:
            return self._data_map[ip][path]

    def _is_forbidden(self, forbidden, request):
        # Cleaning the request path
        req_ip = str(request.client_address[0])
        for req_ip in forbidden:
            return Classification.Detected
        return Classification.NoConclusion

    def _is_legitimate(self, legitimate, request):
        req_path = str(request.path).strip("/")
        req_ip = str(request.client_address[0])
        request_data = "{}<=>{}".format(req_ip, req_path)
        if request_data in legitimate:
            return Classification.Clean
        # For case that the ip has access for all the server path its will be ip only.
        if req_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        # TODO: implement the refresh data from Database.
        return None

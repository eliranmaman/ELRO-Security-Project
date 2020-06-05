import time

from Detectors import Detector, Sensitivity, Classification
from config import brute_force_map as map


# TODO: if there will be enough time int the end we will implement this.

class DDoS(Detector):

    def __init__(self):
        super().__init__()
        self._data_map = map
        self._max_requests = 50

    def detect(self, request, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        The method will check huge increasing in traffic + Proxies using.
        :param request: send the full request object.
        :param sensitivity: The sensitivity of the detecting
        :param forbidden: list of paths to protect
        :param legitimate: The path's that legitimate in any case for cross-site (list)
        :return: boolean
        """
        # ---- Pre Processing Stage ----- #
        check_pre_processing = self._pre_processing(forbidden, legitimate, request)
        if check_pre_processing == Classification.Clean:
            return False
        elif check_pre_processing == Classification.Detected:
            return True
        # ---- Check specific IP ---- #
        client_ip = request.client_address[0]
        if sensitivity == Sensitivity.Regular:
            max_request = 60
            increasing_factor = 8
        elif sensitivity == Sensitivity.Sensitive:
            max_request = 30
            increasing_factor = 4
        else:
            max_request = 15
            increasing_factor = 2
        last_request, counter = self._get_previous_request_info(client_ip)
        if time.time() - last_request > 60: # in sec.
            counter = 1
        self._data_map[client_ip] = time.time(), counter+1
        if counter >= max_request:
            return True
        # ---- Check Increasing Requests + Proxies Increasing ---- #
        # Lets get the last hour data
        proxies_request_num, total_request_num = self._data_map["LAST_HOUR_INFO"]
        # TODO: I'am HERE
        return True

    def _get_previous_request_info(self, ip):
        if ip not in self._data_map:
            return time.time(), 0
        return self._data_map[ip]

    def _is_forbidden(self, forbidden, request):
        return NotImplementedError()

    def _is_legitimate(self, legitimate, request):
        return NotImplementedError()

    def get_forbidden_list(self):
        return NotImplementedError()

    def refresh(self):
        return NotImplementedError()





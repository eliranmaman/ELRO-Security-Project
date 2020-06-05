import time

from Detectors import Detector, Sensitivity, Classification
from config import brute_force_map as map


# TODO: change brute_force_map to come from database
# TODO: tests

class DDoS(Detector):

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
        if check_pre_processing == Classification.NoConclusion:
            return False
        elif check_pre_processing == Classification.Clean:
            return False
        # ------ This code will run if the path is in the forbidden list ------ #
        return NotImplementedError()

    def _get_previous_request_info(self, ip, path):
        return NotImplementedError()

    def _is_forbidden(self, forbidden, request):
        return NotImplementedError()

    def _is_legitimate(self, legitimate, request):
        return NotImplementedError()

    def get_forbidden_list(self):
        return NotImplementedError()

    def refresh(self):
        return NotImplementedError()





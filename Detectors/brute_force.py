import time

from DBAgent.orm import BruteForceDataItem
from Detectors import Detector, Sensitivity, Classification


# TODO: change brute_force_map to come from database
# TODO: tests
from config import db


class BruteForce(Detector):

    def __init__(self):
        super().__init__()
        self.name = "bruteforce_detector"

    def detect(self, parsed_data, sensitivity=Sensitivity.VerySensitive, forbidden=None, legitimate=None):
        """
        The method will check path that are in the forbidden list, for every path in this list
        the method will perform brute force check by number of request in the last 1min.
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :param sensitivity: The sensitivity of the detecting
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
        # ------ This code will run if the path is in the forbidden list ------ #
        req_path = parsed_data.path.strip("/")
        client_ip = parsed_data.from_ip
        bf_item = self._get_previous_request_info(client_ip, req_path, parsed_data.host_name)
        last_request, counter = bf_item.time_stamp, bf_item.counter
        # Sensitivity will determinate the max_counter.
        if sensitivity == Sensitivity.Regular:
            max_counter = 10  # TODO: discuss about the const numbers.
        elif sensitivity == Sensitivity.Sensitive:
            max_counter = 5
        elif sensitivity == Sensitivity.VerySensitive:
            max_counter = 100000
        else:
            max_counter = 3
        # Check if the last request was more that 1min ago
        bf_item.counter += 1
        bf_item.time_stamp = time.time()
        if time.time() - last_request > 60:  # TODO: discuss about the const 1min.
            bf_item.counter = 0
        elif counter >= max_counter:
            db.commit()
            return True
        # --- The counter is < max_counter --- #
        db.commit()
        return False

    def _get_previous_request_info(self, ip, path, dns_name):
        brute_force_data = db.get_session().query(BruteForceDataItem).filter_by(ip=ip, path=path, dns_name=dns_name).first()
        if brute_force_data is None:
            brute_force_data = BruteForceDataItem(ip=ip, dns_name=dns_name, path=path, counter=0, time_stamp=time.time())
            db.insert(brute_force_data)
        return brute_force_data

    def _is_forbidden(self, forbidden, parsed_data):
        """
        The forbidden works on ip black list.
        :param forbidden: list of ips.
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :return: Classification Enum
        """
        for parsed_data.from_ip in forbidden:
            return Classification.Detected
        return Classification.NoConclusion

    def _is_legitimate(self, legitimate, parsed_data):
        """
        The method relay on ip+path access control, for ip that have non limited
        access we put only ip.
        The format is: IP<=>PATH (e.g 127.0.0.1<=>controller.html)
        :param legitimate: list of path & ips in this format IP<=>PATH or just IP for unlimited access
        :param parsed_data: Parsed Data (from the parser module) of the request / response
        :return: Classification Enum
        """
        req_path = parsed_data.path.strip("/")
        request_data = "{}<=>{}".format(parsed_data.from_ip, req_path)
        if request_data in legitimate:
            return Classification.Clean
        # For case that the ip has access for all the server path its will be ip only.
        if parsed_data.from_ip in legitimate:
            return Classification.Clean
        return Classification.NoConclusion

    def get_forbidden_list(self):
        return self._forbidden

    def refresh(self):
        # TODO: implement the refresh data from Database.
        return None

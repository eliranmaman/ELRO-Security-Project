import re
from functools import wraps

from Controllers import Controller
from DBAgent import HttpRequest, Server
from DBAgent.orm import Services, WhiteList, BlackList, HttpResponse
from Detectors.csrf import CSRF
from Detectors.user_protection import UserProtectionDetector
from config import db
from test2 import to_json

"""
100 = Detectors validation failed.
200 = request is ok
"""

# TODO: change const to Enums

def save_to_db(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        error_code, response_to, item, original_request = func(self, *args, **kwargs)
        db.insert(item)
        return error_code, response_to, original_request
    return wrapper


class ElroController(Controller):

    def __init__(self, detectors):
        super().__init__(detectors)
        self._detectors = detectors
        self._db = db
        self._server = None
        self._request = None
        self._response = None

    @save_to_db
    def request_handler(self, parsed_request, original_request):
        """
        :param original_request:
        :param parsed_request:
        :return: tuple(response code, send to code (0 for client,1 for server))
        """
        print("B")
        self._request = parsed_request
        session = db.get_session()
        # Get The Server id from DB
        self._server = session.query(Server).filter_by(server_dns=parsed_request.host_name).first()
        if self._server is None:
            return 404, 0, parsed_request, original_request
        # check if authorized requester.
        print("C")
        is_authorized = self._is_authorized(parsed_request.from_ip)
        if is_authorized == 0:
            return 200, 1, parsed_request, original_request
        elif is_authorized == 1:
            return 100, 0, parsed_request, original_request
        # Get list of detectors for the server
        parsed_request.to_server_id = self._server.item_id
        detectors = self._list_of_detectors(self._server.item_id)
        validate = False
        print("E")
        for detector in detectors:
            # TODO: csrf tokens.
            # TODO: Detectors data (true / false)
            # TODO: we want to check all the detectors or not? (in case of true)
            d = detector()
            print(d)
            validate = validate or d.detect(parsed_request)
            if validate:
                parsed_request.decision = False
                return 100, 0, parsed_request, original_request
        parsed_request.decision = True
        return 200, 1, parsed_request, original_request

    @save_to_db
    def response_handler(self, parsed_response, original_response):
        self._response = parsed_response
        parsed_response.from_server_id = self._server.item_id
        cookies = self._request.headers.get("Cookie", "")
        m = re.match(".*?Elro-Sec-Bit=.*\"(.*?)@Elro-Sec-End", cookies)
        if m is None:
            bit_indicator = 256
        else:
            bit_indicator = int(m.group(1))
        user_protection = UserProtectionDetector(parsed_response)
        results = user_protection.detect(bit_indicator)
        # TODO: add user notification to the response
        return 200, 1, parsed_response, original_response

    def _is_authorized(self, requester_ip):
        """
        0 = white list
        1 = black list
        2 = no data
        :param server:
        :param requester_ip:
        :return:
        """
        session = db.get_session()
        white_list = session.query(WhiteList).filter_by(server_id=self._server.item_id).all()
        black_list = session.query(BlackList).filter_by(server_id=self._server.item_id).all()
        valid = False
        for item in white_list:
            valid = valid or item.ip == requester_ip
            if valid:
                return 0
        for item in black_list:
            valid = valid or item.ip == requester_ip
            if valid:
                return 1
        return 2

    def _list_of_detectors(self, server_id):
        session = db.get_session()
        services = session.query(Services).filter_by(server_id=server_id).first()
        services = to_json(services)
        services.pop("item_id")
        services.pop("created_on")
        services.pop("user_id")
        services.pop("server_id")
        return [self._detectors[key] for key in services]

    def _extra_data(self, server_ip):
        pass
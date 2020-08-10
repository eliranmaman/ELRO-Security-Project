import re
import secrets
from functools import wraps
from http import cookies

from Controllers import Controller
from DBAgent import Server
from DBAgent.orm import Services, WhiteList, BlackList, DetectorRequestData, DetectorDataResponse, to_json, CookiesToken
from Data.enums.controller_enums import ControllerResponseCode, RedirectAnswerTo, IsAuthorized
from Detectors.user_protection import UserProtectionDetector
from config import db


def handle_block(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        response_code, redirect_to, the_request, parsed_request = func(self, *args, **kwargs)
        if response_code == ControllerResponseCode.NotValid:
            parsed_request.host_name = "elro-sec.com"
            parsed_request.path = "/blocked.html"
            the_request.headers.replace_header("Host", "elro-sec.com")
            the_request.path = "/blocked.html"
            # TODO:
            """
            Misdirected Request
            The client needs a new connection for this
            request as the requested host name does not match
            the Server Name Indication (SNI) in use for this
            connection.
            """
        return response_code, redirect_to, the_request, parsed_request
    return wrapper


class ElroController(Controller):

    def __init__(self, detectors):
        super().__init__(detectors)
        self._detectors = detectors
        self._db = db
        self._server = None
        self._request = None
        self._response = None
        self._request_data = None
        self.response_cookie = None

    @handle_block
    def request_handler(self, parsed_request, original_request):
        print("B")
        self._request_data = DetectorRequestData(from_ip=parsed_request.from_ip)
        self._request = parsed_request
        session = db.get_session()
        # Get The Server id from DB
        self._server = session.query(Server).filter_by(server_dns=parsed_request.host_name).first()
        if self._server is None:
            return ControllerResponseCode.Failed, RedirectAnswerTo.Client, original_request, parsed_request
        # check if authorized requester.
        print("C")
        self._request_data.to_server_id = self._server.item_id
        is_authorized = self._is_authorized(parsed_request.from_ip)
        if is_authorized == IsAuthorized.Yes:
            self._request_data.detected = "white_list"
            db.insert(self._request_data)
            return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_request, parsed_request
        elif is_authorized == IsAuthorized.No:
            self._request_data.detected = "black_list"
            db.insert(self._request_data)
            return ControllerResponseCode.NotValid, RedirectAnswerTo.Client, original_request, parsed_request
        # Get list of detectors for the server
        parsed_request.to_server_id = self._server.item_id
        detectors = self._list_of_detectors(self._server.item_id)
        validate = False
        print("E")
        for detector_constructor in detectors:
            detector = detector_constructor()
            print(detector.name)
            validate = detector.detect(parsed_request)
            if detector.name == "1cookie_poisoning_detector" and validate:
                # Detected => Removing cookies.
                original_request.headers.replace_header("Cookie", "")
            elif detector.name == "1cookie_poisoning_detector":
                # Creating new token
                self.response_cookie = CookiesToken(dns_name=parsed_request.host_name, ip=parsed_request.from_ip,
                                                    active=True, token=secrets.token_hex(256))
            elif validate:
                print("Detected ==================================> ", detector.name)
                self._request_data.detected = detector.name
                db.insert(self._request_data)
                parsed_request.decision = False
                return ControllerResponseCode.NotValid, RedirectAnswerTo.Client, original_request, parsed_request
        parsed_request.decision = True
        self._request_data.detected = "none"
        db.insert(self._request_data)
        return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_request, parsed_request

    def response_handler(self, parsed_response, original_response):
        self._response = parsed_response
        parsed_response.from_server_id = self._server.item_id
        res_cookies = self._request.headers.get("Cookie", "")
        m = re.match(".*?Elro-Sec-Bit=.*\"(.*?)@Elro-Sec-End", res_cookies)
        bit_indicator = 256 if m is None else int(m.group(1))
        user_protection = UserProtectionDetector(parsed_response)
        results = user_protection.detect(bit_indicator)
        detector_data = DetectorDataResponse(request_id=self._request_data.item_id,
                                             from_server_id=parsed_response.from_server_id,
                                             to_ip=parsed_response.to_ip)
        db.insert(detector_data)
        if type(self.response_cookie) is CookiesToken:
            # Find the old token
            session = db.get_session()
            old_cookie = session.query(CookiesToken). \
                filter_by(active=True, ip=self._request.from_ip,
                          dns_name=self._request.host_name).first()
            if old_cookie is not None:
                old_cookie.active = False
                session.commit()
            # Insert the new token
            db.insert(self.response_cookie)
            # Update the response with the new token.
            cookie = cookies.SimpleCookie()
            cookie['Elro-Sec-Token'] = "{}@Elro-Sec-End".format(self.response_cookie.token)
            cookie['Elro-Sec-Token']['max-age'] = 2592000  # 30 days
            original_response.headers["Set-Cookie"] = cookie
        # TODO: add user notification to the response
        return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_response

    def _is_authorized(self, requester_ip):
        """
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
                return IsAuthorized.Yes
        for item in black_list:
            valid = valid or item.ip == requester_ip
            if valid:
                return IsAuthorized.No
        return IsAuthorized.NoData

    def _list_of_detectors(self, server_id):
        session = db.get_session()
        services = session.query(Services).filter_by(server_id=server_id).first()
        services = to_json(services, ignore_list=["item_id", "created_on", "user_id", "server_id"])
        return [self._detectors[key] for key in services]

    def _extra_data(self, server_ip):
        pass

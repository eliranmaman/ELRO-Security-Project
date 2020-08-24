import re
import secrets
from functools import wraps
from http import cookies

from Controllers import Controller
from DBAgent import Services, WhiteList, BlackList, DetectorRequestData, DetectorDataResponse, CookiesToken, Server
from Knowledge_Base import to_json, ControllerResponseCode, RedirectAnswerTo, IsAuthorized, log
from Detectors import UserProtectionDetector, UserProtectionResults
from Knowledge_Base.enums.logs_enums import LogLevel
from config import db


# TODO: 1) Its making a circle click "approve" => blocked from brute force => show user protection => click "approve" => ... => ... (I think it's done.)
#       2) SQL Detector (validator) how to put it in ?
#       3) deploy on the server (doron need to open the 80, 443, 22 port for network out)
#       4)


def handle_block(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        response_code, redirect_to, the_request, parsed_request = func(self, *args, **kwargs)
        if response_code == ControllerResponseCode.NotValid:
            parsed_request.host_name = self.kb["blocked_url"]
            parsed_request.path = self.kb["blocked_path"]
            parsed_request.query = ""
        return response_code, redirect_to, the_request, parsed_request

    return wrapper


def modify_response(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        detector_result, redirect_to, the_response = func(self, *args, **kwargs)
        if detector_result.bit_map == self.kb["clean_bit"] or self.kb["file_type"] not in the_response.headers.get('Content-Type', ""):
            return ControllerResponseCode.Valid, redirect_to, the_response.content
        with open(self.kb["safe_place_path"], "r") as file:
            new_content = file.read()
        to_add = "".join([self.kb["join_format"].format(i) for i in detector_result.detected_alerts])
        if detector_result.csrf_js_files:
            csrf_js_files = self.kb["csrf_files_alert_format"].format("".join([self.kb["join_format"].format(i) for i in detector_result.csrf_urls]))
        else:
            csrf_js_files = ""
        new_content = new_content.replace(self.kb["js_file_code"], csrf_js_files)
        new_content = new_content.replace(self.kb["activities_code"], to_add, 1)
        new_content = new_content.replace(self.kb["location_code"], str(self._request.path), 1)
        new_cookie_value = cookies.SimpleCookie()
        new_cookie_value['Elro-Sec-Bit'] = self.kb["elro_sec_bit_format"].format(self._bit_indicator ^ detector_result.bit_map)
        new_cookie_value['Elro-Sec-Bit']['max-age'] = 2592000  # 30 days
        new_content = new_content.replace(self.kb["new_bit_code"], str(new_cookie_value).replace("Set-Cookie:", "", 1))
        send_content = bytes(new_content.encode('utf_8'))
        return ControllerResponseCode.NotValid, redirect_to, send_content

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
        self._bit_indicator = 255

    @handle_block
    def request_handler(self, parsed_request, original_request):
        if original_request.headers.get('sec-fetch-dest', "") in ["script", "style"]:
            return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_request, parsed_request
        self._request_data = DetectorRequestData(from_ip=parsed_request.from_ip)
        self._request = parsed_request
        session = db.get_session()
        # Get The Server id from DB
        log("Looking for the server on the DataBase {}".format(parsed_request.host_name), LogLevel.DEBUG, self.request_handler)
        self._server = session.query(Server).filter_by(server_dns=parsed_request.host_name).first()
        if self._server is None:
            log("Server not found at the DataBase {}".format(parsed_request.host_name), LogLevel.DEBUG, self.request_handler)
            return ControllerResponseCode.Failed, RedirectAnswerTo.Client, original_request, parsed_request
        # check if authorized requester.
        self._request_data.to_server_id = self._server.item_id
        log("Activate _is_authorized method", LogLevel.DEBUG, self.request_handler)
        is_authorized = self._is_authorized(parsed_request.from_ip)
        if is_authorized == IsAuthorized.Yes:
            log("_is_authorized method results is Yes", LogLevel.DEBUG, self.request_handler)
            self._request_data.detected = "white_list"
            db.insert(self._request_data)
            return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_request, parsed_request
        elif is_authorized == IsAuthorized.No:
            log("_is_authorized method results is No", LogLevel.DEBUG, self.request_handler)
            self._request_data.detected = "black_list"
            db.insert(self._request_data)
            return ControllerResponseCode.NotValid, RedirectAnswerTo.Client, original_request, parsed_request
        # Get list of detectors for the server
        log("_is_authorized method results is NoConclusions", LogLevel.DEBUG, self.request_handler)
        parsed_request.to_server_id = self._server.item_id
        log("Activate _list_of_detectors method", LogLevel.DEBUG, self.request_handler)
        detectors = self._list_of_detectors(self._server.item_id)
        log("_list_of_detectors results is {}".format(detectors), LogLevel.DEBUG, self.request_handler)
        for detector_constructor in detectors:
            detector = detector_constructor()
            validate = detector.detect(parsed_request)
            if detector.name in self.kb["non_blocking_detectors"] and validate:
                # Detected => Removing cookies.
                original_request.headers.replace_header("Cookie", "")
            elif detector.name in self.kb["non_blocking_detectors"]:
                # Creating new token
                self.response_cookie = CookiesToken(dns_name=parsed_request.host_name, ip=parsed_request.from_ip,
                                                    active=True, token=secrets.token_hex(256))
            elif validate:
                log(" ************* Detector {} is detected unusual activity for {} ************".format(detector.name, original_request.url), LogLevel.INFO, self.request_handler)
                self._request_data.detected = detector.name
                log("Insert Information to database".format(detector.name), LogLevel.DEBUG, self.request_handler)
                db.insert(self._request_data)
                parsed_request.decision = False
                return ControllerResponseCode.NotValid, RedirectAnswerTo.Client, original_request, parsed_request
        log("Nothing unusual detected by the detectors.", LogLevel.INFO, self.request_handler)
        parsed_request.decision = True
        self._request_data.detected = "none"
        log("Insert Information to database", LogLevel.DEBUG, self.request_handler)
        db.insert(self._request_data)
        return ControllerResponseCode.Valid, RedirectAnswerTo.Server, original_request, parsed_request

    @modify_response
    def response_handler(self, parsed_response, original_response):
        # If the response is the block page => don't activate the response detector.
        if self.kb["blocked_url"] in self._request.host_name and self._request.path == self.kb["blocked_path"]:
            return UserProtectionResults(), RedirectAnswerTo.Client, original_response
        self._response = parsed_response
        parsed_response.from_server_id = self._server.item_id
        res_cookies = self._request.headers.get("Cookie", "")
        m = re.match(".*?Elro-Sec-Bit=.*\"(\d*)@Elro-Sec-End", res_cookies)
        self._bit_indicator = 255 if m is None else int(m.group(1))
        user_protection = UserProtectionDetector(parsed_response)
        results = user_protection.detect(self._bit_indicator)
        detector_data = DetectorDataResponse(request_id=self._request_data.item_id,
                                             from_server_id=parsed_response.from_server_id,
                                             to_ip=parsed_response.to_ip)
        db.insert(detector_data)
        # User Protection Bit
        if m is None and self.kb["file_type"] in self._request.headers.get("Content-Type", ""):
            bit_cookie = cookies.SimpleCookie()
            bit_cookie['Elro-Sec-Bit'] = self.kb["elro_sec_bit_format"].format(self._bit_indicator)
            bit_cookie['Elro-Sec-Bit']['max-age'] = 2592000  # 30 days
            original_response.headers["Set-Cookie"] = bit_cookie
        return results, RedirectAnswerTo.Client, original_response

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
        services = to_json(services, ignore_list=self.kb["ignore_list"])
        return [self._detectors[key] for key in services if key in self._detectors and services[key]]

    def _extra_data(self, server_ip):
        pass

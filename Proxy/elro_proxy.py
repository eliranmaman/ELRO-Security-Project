import logging
import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import requests

from Controllers.elro_controller import ElroController
from Data.enums.controller_enums import ControllerResponseCode
from Detectors.csrf import CSRF
from Parser import BaseHTTPRequestParser
from Parser.parser import HTTPResponseParser

from Proxy import Proxy
from config import server
from config import log_dict
from Detectors import SQLDetector, BruteForce, BotsDetector, XSSDetector, XMLDetector


# sys.stderr = open(log_dict + "/basic_proxy.log", 'a+')
# handler = logging.StreamHandler(sys.stderr)
# handler.setLevel(logging.ERROR)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)


class BasicProxy2(Proxy):
    def __init__(self, port, logger=None):
        super().__init__(port, logger)
        self._httpd = None

    def start(self):
        if not self._running:
            self._running = True
            server_address = (server["address"], 80)
            self._httpd = ThreadingHTTPServer(server_address, BasicProxy2.RequestHandler2)
            # self._httpd.socket = ssl.wrap_socket(self._httpd.socket,
            #                                      certfile='/etc/letsencrypt/live/elro.cs.colman.ac.il/fullchain.pem',
            #                                      keyfile='/etc/letsencrypt/live/elro.cs.colman.ac.il/privkey.pem',
            #                                      server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
            print('Proxy is alive: \n\tPort: {}\n\tAddress: {}'.format(self._port, server["address"]))
            self._httpd.serve_forever()  # should be in another Thread.
        else:
            print("Proxy is already alive at: \n\tAddress: {}\n\tPort: {}".format(server["address"], self._port))

    def stop(self):
        if self._running:
            self._running = False
            self._httpd.server_close()
        else:
            print("Proxy is not running")

    class RequestHandler2(BaseHTTPRequestHandler):
        Controller = Proxy._controller

        def do_HEAD(self):
            self.do_GET(body=False)

        def do_GET(self, body=True):
            print("0) Request Arrived")
            sent = False
            try:
                detectors = {
                    # "sql_detector": SQLDetector,
                    "xss_detector": XSSDetector,
                    "xml_detector": XMLDetector,
                    "csrf_detector": CSRF,
                    "bruteforce_detector": BruteForce,
                    "bots_detector": BotsDetector,
                }
                print("1) Parse Request")
                parser = BaseHTTPRequestParser()
                parsed_request = parser.parse(self)
                print("2) Controller")
                controller = ElroController(detectors=detectors)
                response_code, send_to, new_request, parsed_request = controller.request_handler(parsed_request, self)
                print("3) Parse headers")
                req_header = new_request.parse_headers()
                url = 'https://{}{}?{}'.format("195.201.169.229/~curlcom/elro-sec.com", parsed_request.path, parsed_request.query)
                print(url)
                if response_code == ControllerResponseCode.NotValid:
                    print("4) Not Valid")
                    self.send_response(302)
                    self.send_header('Location', url)
                    self.end_headers()
                elif response_code == ControllerResponseCode.Valid:
                    print("4) Valid, Asking for {}".format(url))
                    resp = requests.get(url, headers=self.merge_two_dicts(req_header, self.set_header(parsed_request.host_name)), verify=False)
                    print(resp)
                    print("4.1) Request Arrived")
                    parser = HTTPResponseParser(parsed_request)
                    print("5) Parse Response")
                    parsed_response = parser.parse(resp)
                    print("6) Controller")
                    response_code, send_to, new_content = controller.response_handler(parsed_response, resp)
                    if response_code == ControllerResponseCode.NotValid:
                        send_content = new_content
                    else:
                        send_content = resp.content
                    sent = True
                    resp.headers['Content-Length'] = "{}".format(len(send_content))
                    print("7) Send Response")
                    self.send_response(resp.status_code)
                    print("8) Send Header")
                    self.send_resp_headers(resp)
                    if body:
                        print("9) Send Body")
                        self.wfile.write(send_content)
                    return
                else:
                    # The response is failed. (e.g server is not exist in the DB).
                    print("4) Send 404")
                    self.send_error(404, 'error trying to proxy')
            except Exception as e:
                print(e)
            finally:
                self.finish()
                if not sent:
                    self.send_error(404, 'error trying to proxy')

        def do_POST(self, body=True):
            sent = False
            try:
                detectors = {
                    "sql_detector": SQLDetector,
                    "xss_detector": XSSDetector,
                    "xml_detector": XMLDetector,
                    "csrf_detector": CSRF,
                    "bruteforce_detector": BruteForce,
                    "bots_detector": BotsDetector,
                }
                parser = BaseHTTPRequestParser()
                parsed_request = parser.parse(self)
                controller = ElroController(detectors=detectors)
                response_code, send_to, new_request, parsed_request = controller.request_handler(parsed_request, self)
                req_header = new_request.parse_headers()
                url = 'https://{}{}'.format(parsed_request.host_name, parsed_request.path)
                content_len = int(self.headers.get('content-length', 0))
                post_body = self.rfile.read(content_len).decode("utf-8")
                if response_code == ControllerResponseCode.NotValid:
                    self.send_response(302)
                    self.send_header('Location', url)
                    self.end_headers()
                else:
                    resp = requests.post(url, headers=self.merge_two_dicts(req_header, self.set_header(parsed_request.host_name)), verify=False, data=post_body)
                    parser = HTTPResponseParser(parsed_request)
                    parsed_response = parser.parse(resp)
                    response_code, send_to, new_content = controller.response_handler(parsed_response, resp)
                    if response_code == ControllerResponseCode.NotValid:
                        send_content = new_content
                    else:
                        send_content = resp.content
                    sent = True
                    resp.headers['Content-Length'] = "{}".format(len(send_content))
                    self.send_response(resp.status_code)
                    self.send_resp_headers(resp)
                    if body:
                        self.wfile.write(send_content)
                    return
            except Exception as e:
                print(e)
            finally:
                self.finish()
                if not sent:
                    self.send_error(404, 'error trying to proxy')

        def parse_headers(self):
            req_header = {}
            for key, value in self.headers.items():
                req_header[key] = value
            return req_header

        def send_resp_headers(self, resp):
            respheaders = resp.headers
            for key in respheaders:
                if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding',
                               'content-length', 'Content-Length']:
                    self.send_header(key, respheaders[key])
            self.send_header('Content-Length', respheaders.get('Content-Length', len(resp.content)))
            self.end_headers()

        def merge_two_dicts(self, x, y):
            z = x.copy()  # start with x's keys and values
            z.update(y)  # modifies z with y's keys and values & returns None
            return z

        def set_header(self, hostname):
            headers = {
                'Host': hostname
            }

            return headers

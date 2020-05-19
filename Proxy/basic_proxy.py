import datetime
import random
import string
from http import cookies
import logging
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from config import cookies_map


from Detectors.cookies_poisoning import CookiesPoisoning
from Detectors.csrf import CSRF
from Proxy import Proxy
from config import server
from config import log_dict
from Detectors import SQLDetector, BruteForce

hostname2 = "www.google.com"

sys.stderr = open(log_dict+"/basic_proxy.log", 'a+')
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)


class BasicProxy(Proxy):
    def __init__(self, port, logger=None):
        super().__init__(port, logger)
        self._httpd = None

    def start(self):
        if not self._running:
            self._running = True
            server_address = (server["address"], self._port)
            self._httpd = HTTPServer(server_address, BasicProxy.RequestHandler)
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

    class RequestHandler(BaseHTTPRequestHandler):
        Controller = Proxy._controller
        def do_HEAD(self):
            self.do_GET(body=False)

        def do_GET(self, body=True):
            sent = False
            try:
                url = 'https://{}{}'.format(hostname2, self.path)
                # content_len = int(self.headers.get('content-length', 0))
                # post_body = self.rfile.read(content_len).decode("utf-8")
                req_header = self.parse_headers()
                detector = BruteForce()
                print("Detecting .....")
                check = detector.detect(self)
                # print("Finish .....")
                if check is True:
                    print("Busted, Communication is down!")
                    req_header['Cookie'] = None
                # else:
                #     print("verify completed, Welcome back {}".format(self.client_address))
                resp = requests.get(url, headers=self.merge_two_dicts(req_header, self.set_header()), verify=False)
                sent = True
                if check is True:
                    resp.headers['CSRF_TOKEN'] = "Got u"
                # if resp.cookies and not check:
                    # secret_value = "{}@Elro-Sec-End".format(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(100)))
                    # key = detector.generate_key(self.client_address[0], self.headers.get('Host', "elro-sec.com"))
                    # cookies_map[key] = secret_value
                    # cookie = cookies.SimpleCookie()
                    # cookie['Elro-Sec-Token'] = secret_value
                    # cookie['Elro-Sec-Token']['max-age'] = 2592000  # 30 days
                    # resp.headers["Set-Cookie"] = cookie
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    self.wfile.write(resp.content)
                return
            except Exception as e:
                print(e)
            finally:
                self.finish()
                if not sent:
                    self.send_error(404, 'error trying to proxy')

        def do_POST(self, body=True):
            sent = False
            try:
                url = 'https://{}{}'.format(hostname2, self.path)
                content_len = int(self.headers.get('content-length', 0))
                post_body = self.rfile.read(content_len).decode("utf-8")
                req_header = self.parse_headers()
                detector = BruteForce()
                check = detector.detect(self)
                if check:
                    print("Busted...")
                else:
                    print("Not yet...")
                # print(req_header.get('referer', 'No'))
                resp = requests.post(url, data=post_body, headers=self.merge_two_dicts(req_header, self.set_header()),
                                     verify=False)
                if check:
                    resp.headers['CSRF_TOKEN'] = "Got u"
                sent = True

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    self.wfile.write(resp.content)
                return
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
            self.send_header('Content-Length', len(resp.content))
            self.end_headers()

        def merge_two_dicts(self, x, y):
            z = x.copy()  # start with x's keys and values
            z.update(y)  # modifies z with y's keys and values & returns None
            return z

        def set_header(self):
            headers = {
                'Host': hostname2
            }

            return headers
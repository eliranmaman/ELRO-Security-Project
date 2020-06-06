import logging
import sys
import requests
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from Proxy import Proxy
from config import server


from config import log_dict
from Detectors import SQLDetector, SQLValidator, XMLDetector, Sensitivity

hostname2 = "www.facebook.com"
SQL_THRESHOLD = 0.5
sys.stderr = open(log_dict+"/basic_proxy.log", 'a+')
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)


class BasicTestProxyRoyi(Proxy):
    def __init__(self, port, logger=None):
        super().__init__(port, logger)
        self._httpd = None

    def start(self):
        if not self._running:
            self._running = True
            server_address = (server["address"], self._port)
            self._httpd = HTTPServer(server_address, BasicTestProxyRoyi.RequestHandler)
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
                print()
                url = 'https://{}{}'.format(hostname2, self.path)
                req_header = self.parse_headers()
                xml_det = XMLDetector()
                headers = self.headers
                params = self.path
                content_len = int(self.headers.get('Content-Length', 0))
                body = str(self.rfile.read(content_len))[2:-1]
                malicious_body = xml_det.detect(body)
                to_block = malicious_body
                if to_block:
                    print("xml attack detected in the body!!")
                    self.send_error(403, 'Access Denied, XML ATTACK DETECTED!')
                    return
                malicious_headers = xml_det.detect(headers)
                to_block = malicious_headers
                if to_block:
                    print("xml attack detected in the headers!!")
                    self.send_error(403, 'Access Denied, XML ATTACK DETECTED!')
                    return
                malicious_params = xml_det.detect(params)
                to_block = malicious_params
                if to_block:
                    print("xml attack detected in the params!!")
                    self.send_error(403, 'Access Denied, XML ATTACK DETECTED!')
                    return

                resp = requests.get(url, headers=self.merge_two_dicts(req_header, self.set_header()), verify=False)
                sent = True
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    print('sending response....')
                    print(resp.content)
                    self.wfile.write(resp.content)
                return
            finally:
                self.finish()
                if not sent:
                    self.send_error(404, 'error trying to proxy')

        def do_POST(self, body=True):
            sent = False
            try:
                url = 'https://{}{}'.format(hostname2, self.path)
                content_len = int(self.headers.get('content-length', 0))
                post_body = self.rfile.read(content_len)
                req_header = self.parse_headers()
                sql_det = SQLDetector()
                sql_validator = SQLValidator()
                headers = self.headers
                params = self.path
                body = str(post_body)[2:-1]
                malicious_headers = sql_det.detect(headers, sensitivity=Sensitivity.Sensitive)
                to_block = malicious_headers
                if to_block:
                    print("sql attack detected in the headers!!")
                    self.send_error(403, 'Access Denied, SQL ATTACK DETECTED!')
                    return
                malicious_body = sql_det.detect(body)
                to_block = malicious_body
                if to_block:
                    assurance_percent = sql_validator.validate(body)
                    print('total', assurance_percent)
                    if assurance_percent >= SQL_THRESHOLD:
                        print(assurance_percent)
                        print("sql attack detected in the body!!")
                        self.send_error(403, 'Access Denied, SQL ATTACK DETECTED!')
                        return
                    else:
                        post_body = re.escape(post_body)
                        print("sending escaped body\n", post_body)

                malicious_params = sql_det.detect(params, sensitivity=Sensitivity.Sensitive)
                to_block = malicious_params
                if to_block:
                    print("sql attack detected in the params!!")
                    self.send_error(403, 'Access Denied, SQL ATTACK DETECTED!')
                    return
                resp = requests.post(url, data=post_body, headers=self.merge_two_dicts(req_header, self.set_header()),
                                     verify=False)
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

        # def detect_sql_injection(self, content):

        def parse_headers(self):
            req_header = {}
            for line in self.headers:
                line_parts = [o.strip() for o in line.split(':', 1)]
                if len(line_parts) == 2:
                    req_header[line_parts[0]] = line_parts[1]
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

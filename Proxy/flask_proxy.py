import requests
from flask import Flask, request, Response, abort

from Controllers.elro_controller import ElroController
from Data.enums.controller_enums import ControllerResponseCode
from Detectors import SQLDetector, BruteForce, BotsDetector, XSSDetector, XMLDetector
from Detectors.csrf import CSRF
from Parser.parser import FlaskHTTPRequestParser, HTTPResponseParser

app = Flask(__name__)

detectors = {
    # "sql_detector": SQLDetector,
    "xss_detector": XSSDetector,
    "xml_detector": XMLDetector,
    "csrf_detector": CSRF,
    "bruteforce_detector": BruteForce,
    "b"
    "ots_detector": BotsDetector,
}


def reqest_handler():
    print("1) Parse Request")
    parser = FlaskHTTPRequestParser()
    parsed_request = parser.parse(request)
    print("2) Controller")
    controller = ElroController(detectors=detectors)
    response_code, send_to, new_request, parsed_request = controller.request_handler(parsed_request, request)
    print("3) Parse headers")
    url = 'https://{}{}?{}'.format(parsed_request.host_name, parsed_request.path, parsed_request.query)
    print(url)
    if response_code == ControllerResponseCode.NotValid:
        print("4) Not Valid")
        response = Response(status=302, headers={"Location": url})
    elif response_code == ControllerResponseCode.Valid:
        print("4) Valid, Asking for {}".format(url))
        resp = requests.request(
            method=parsed_request.method, url=url, verify=False
        )
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
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(send_content, resp.status_code, headers)
    else:
        print("4) Not Found")
        response = Response(status=404)
        abort(404)  # Abort the request.
    print("7) Send Response")
    return response


@app.route('/', defaults={'path': ""}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])
def proxy(path):
    print("0) Request Arrived (path: {})".format(path))
    return reqest_handler()


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SECRET_KEY'] = 'super secret key'
    # sess.init_app(app)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run(port=80)

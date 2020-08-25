import requests
from flask import Flask, request, Response, abort
from werkzeug.routing import Rule

from Controllers.elro_controller import ElroController
from HttpsEnforcer import HSTS
from Knowledge_Base import log, to_json, ControllerResponseCode, LogLevel
from Detectors import SQLDetector, BruteForce, BotsDetector, XSSDetector, XMLDetector
from Detectors.csrf import CSRF
from Parser.parser import FlaskHTTPRequestParser, HTTPResponseParser

app = Flask(__name__)
app.url_map.add(Rule('/', endpoint='proxy', defaults={'path': ""}))
app.url_map.add(Rule('/<path:path>', endpoint='proxy'))

# The available detectors for the Controller
detectors = {
    # "sql_detector": SQLDetector,
    # "xss_detector": XSSDetector,
    # "xml_detector": XMLDetector,
    "csrf_detector": CSRF,
    "bruteforce_detector": BruteForce,
    "bots_detector": BotsDetector,
}

hsts = HSTS()


def request_handler():
    try:
        log("Is the request is HTTPS? ", LogLevel.INFO, request_handler)
        if not request.is_secure:
            return Response(status=301, headers=hsts.enforce(request.url))
        log("Start parsing the request", LogLevel.INFO, request_handler)
        parser = FlaskHTTPRequestParser()
        parsed_request = parser.parse(request)
        log("Creating Controller", LogLevel.INFO, request_handler)
        log("The Controller Detectors are {}".format(detectors), LogLevel.DEBUG, request_handler)
        controller = ElroController(detectors=detectors)
        log("Activating controller request handler", LogLevel.INFO, request_handler)
        response_code, send_to, new_request, parsed_request = controller.request_handler(parsed_request, request)
        log("Controller response is: {} {}".format(response_code, send_to), LogLevel.DEBUG, request_handler)
        url = 'https://{}{}?{}'.format(parsed_request.host_name, parsed_request.path, parsed_request.query)
        if response_code == ControllerResponseCode.NotValid:
            log("The Request for {} is not valid.".format(request.url), LogLevel.INFO, request_handler)
            log("Redirecting to {}".format(url), LogLevel.INFO, request_handler)
            response = Response(status=302, headers={"Location": url})
        elif response_code == ControllerResponseCode.Valid:
            send_headers = {key:value for key, value in new_request.headers}
            log("The Request for {} valid and OK".format(request.url), LogLevel.INFO, request_handler)
            resp = requests.request(
                method=parsed_request.method, url=url, verify=True,
                json=new_request.get_json(), headers=send_headers, params=new_request.args,
                data=new_request.form
            )
            log("The Response is {}".format(to_json(resp)), LogLevel.DEBUG, request_handler)
            parser = HTTPResponseParser(parsed_request)
            log("Parse the response", LogLevel.INFO, request_handler)
            parsed_response = parser.parse(resp)
            log("Activating controller response handler", LogLevel.INFO, request_handler)
            response_code, send_to, new_content = controller.response_handler(parsed_response, resp)
            log("Controller response is: {} {}".format(response_code, send_to), LogLevel.DEBUG, request_handler)
            if response_code == ControllerResponseCode.NotValid:
                send_content = new_content
            elif response_code == ControllerResponseCode.Valid:
                send_content = resp.content
            else:
                send_content = None
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
            log("Generating response...", LogLevel.INFO, request_handler)
            response = Response(status=403) if send_content is None else Response(send_content, resp.status_code, headers)
        else:
            log("The Request for {} is not found in the database".format(request.url), LogLevel.INFO, request_handler)
            response = Response(status=404)
            abort(404)  # Abort the request.
        log("Sending response", LogLevel.INFO, request_handler)
        return response
    except Exception as e:
        response = Response(status=404)
        abort(404)  # Abort the request.
        return response



@app.endpoint('proxy')
def proxy(path):
    log("Request has arrived: {} From {}".format(request.url, request.remote_addr), LogLevel.INFO, request_handler)
    return request_handler()


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SECRET_KEY'] = 'super secret key'
    # sess.init_app(app)
    app.debug = True
    app.run(port=80)

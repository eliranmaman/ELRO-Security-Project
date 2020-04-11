import os

import requests
from flask import Flask, request, Response, session
from flask_session import Session  # new style
# from flask.ext.session import Session  # old style

app = Flask(__name__)
# sess = Session()



@app.route('/', methods=['POST', 'GET'])
def index():
    response = None
    if request.method=='GET':
        print("GET")
        # if session.get('key', 'not-set') != "value":
        #     return "Cheater"
        # session['key'] = "value"
        print(request.headers)
        resp = requests.get(f'{"http://www.eliranm.co"}')
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in     resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        # print(response.headers)
    else:
        print("Post")
        print(request.headers)
        resp = requests.get(f'{"http://www.eliranm.co"}')
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in     resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        # print(response.headers)
    return response


@app.route('/<path:path>')
def proxy(path):
    response = None
    if request.method=='GET':
        print(request.headers)
        resp = requests.get(f'{"http://www.eliranm.co/"}{path}')
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in     resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        # print(response.headers)
    else:
        resp = requests.get(f'{"http://www.eliranm.co/"}{path}')
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in     resp.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(resp.content, resp.status_code, headers)
        # print(response.headers)
    return response


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SECRET_KEY'] = 'super secret key'
    # sess.init_app(app)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run(port=80)

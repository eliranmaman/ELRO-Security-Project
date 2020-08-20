from Proxy.flask_proxy import app


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SECRET_KEY'] = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.debug = True
    app.run(host="0.0.0.0", port=9898)
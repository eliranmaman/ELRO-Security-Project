import parser

import requests
from flask import Flask, request
from flask_restful import Resource, Api
import passlib
from passlib.handlers.sha2_crypt import sha256_crypt


from DBAgent.orm import Users
from Detectors.user_protection import UserProtectionDetector
from config import db
app = Flask(__name__)
api = Api(app)


class LoginHandler(Resource):
    def post(self):

        return {'hello': 'world'}

    def get(self):
        session = db.get_session()
        user = db.get_session().query(Users).get(1)
        # session.query(Users).filter_by(active=True).all() / .first()
        # session.query(Users).filter_by(active=True).order_by(DESC(Users.id).all() / .first()
        user.email = "royi@gmail.com"
        print(user.email)
        session.commit()
        return {}


class RegisterHandler(Resource):
    def post(self):
        return {'bla': 'world'}


class GetActiveServicesHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class GetUsersDataHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class GetCustomersStatisticsHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class UpdateServiceStatusHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class AdminUpdateServiceStatusHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class AddNewWebsiteHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class UserProtectorHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        host_to_protect = incoming_json['host_name']
        print("adsdasdasdadasdas", host_to_protect)
        response = requests.get(host_to_protect)
        upc = UserProtectionDetector(response)
        resp = upc.detect()
        return {
            "alerts": resp.security_alerts
        }
        # return {'bye': 'world'}


api.add_resource(LoginHandler, '/login')
api.add_resource(RegisterHandler, '/register')
api.add_resource(GetActiveServicesHandler, '/getActiveServices')
api.add_resource(GetUsersDataHandler, '/getUsersData')
api.add_resource(GetCustomersStatisticsHandler, '/getCustomersStatistics')
api.add_resource(UpdateServiceStatusHandler, '/updateServiceStatus')
api.add_resource(AdminUpdateServiceStatusHandler, '/adminUpdateServiceStatus')
api.add_resource(AddNewWebsiteHandler, '/addNewWebsite')
api.add_resource(UserProtectorHandler, '/userProtector')

if __name__ == '__main__':
    app.run(debug=True)

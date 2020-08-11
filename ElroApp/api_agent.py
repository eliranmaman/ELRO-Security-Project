import json
import parser

import requests
from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps, loads, JSONEncoder, JSONDecoder

import passlib
from passlib.handlers.sha2_crypt import sha256_crypt
from sqlalchemy.orm import load_only, Session
from sqlalchemy import update

from DBAgent.orm import Users, Services, Servers
from Detectors.user_protection import UserProtectionDetector
from config import db

app = Flask(__name__)
api = Api(app)


class LoginHandler(Resource):
    def post(self):
        print("login")
        incoming_json = request.get_json()
        stored_user = db.get_session().query(Users).filter(Users.email == incoming_json['email']).one()
        print(stored_user.password)
        decrypted_stored_user = db.decrypt(stored_user)
        password = decrypted_stored_user.password
        print("from DB:" + password)
        print("incoming:" + incoming_json['password'])
        if password == incoming_json['password']:
            if decrypted_stored_user.is_admin == 1:
                print("res 2")
                return 2
            print("res 1")
            return 1
        print("res 0")
        return 0

    def get(self):
        session = db.get_session()
        user = db.get_session().query(Users).get(1)
        # session.query(Users).filter_by(active=True).all() / .first()
        # session.query(Users).filter_by(active=True).order_by(DESC(Users.id).all() / .first()
        user.email = "royi@gmail.com"
        print(user.email)
        session.commit()
        return {}


def get_user_id_by_email(email):
    user = db.get_session().query(Users).filter(Users.email == email).first()
    return user.item_id


def create_services_object(user_id, incoming_json, server_id):
    print("adding new services object to db")
    print(user_id)
    print(incoming_json)
    print(server_id)
    print("|***&*&*&******")
    users_services = Services(user_id=user_id,
                              sql_detector=int(incoming_json['services']['sql_detector']),
                              bots_detector=int(incoming_json['services']['bots_detector']),
                              xss_detector=int(incoming_json['services']['xss_detector']),
                              xml_detector=int(incoming_json['services']['xml_detector']),
                              csrf_detector=int(incoming_json['services']['csrf_detector']),
                              cookie_poisoning_detector=int(incoming_json['services']['cookie_poisoning_detector']),
                              bruteforce_detector=int(incoming_json['services']['bruteforce_detector']),
                              server_id=server_id)
    return users_services


class RegisterHandler(Resource):
    """ registers a new client, and his protection preferences """

    def post(self):
        print("registering")
        incoming_json = request.get_json()
        print(incoming_json)
        user = Users(email=incoming_json['users']['email'], password=incoming_json['users']['password'])
        db.insert(user)
        user_id = user.item_id
        server = Servers(user_id=user_id,
                         server_ip=incoming_json['services']['ip'],
                         server_dns=incoming_json['services']['website'])
        db.insert(server)
        server_id = server.item_id
        user_services = create_services_object(user_id=user_id, incoming_json=incoming_json, server_id=server_id)
        try:
            db.insert(user_services)
            print("SUCCESS!!!")
            return 1
        except Exception as e:
            print("ERROR!!!")
            print(e)
            return 0


def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)

    return obj

from sqlalchemy.ext.declarative import DeclarativeMeta

class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data) # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields

        return json.JSONEncoder.default(self, obj)


class GetActiveServicesHandler(Resource):
    def post(self):
        print("GetActiveServices")
        incoming_json = request.get_json()
        user_id = get_user_id_by_email(email=incoming_json["email"])
        try:
            print("GetActiveServicesHandler")
            print("user: ==>", user_id)
            joined_statuses = []
            joined_blocked = []
            all_servers = db.get_session().query(Servers).filter(Servers.user_id == user_id).all()
            for server in all_servers:
                services = db.get_session().query(Services).filter(Services.server_id == server.item_id).one()
                joined_object = {**to_json(services), **to_json(server)}
                joined_object['website'] = joined_object['server_dns']
                del joined_object['server_dns']
                joined_statuses.append(joined_object)
            # final_return_json = {"active_status": joined_statuses, "blocked_count": joined_blocked}
            # print(final_return_json)
            # return final_return_json
            return joined_statuses

        except Exception as e:
            print("error", e)
            return False


def to_json(item):
    json_data = dict()
    for attr, value in item.__dict__.items():
        if "_sa_instance_state" in attr:
            continue
        json_data[attr] = str(value)

    return json_data


class GetUsersDataHandler(Resource):
    def post(self):
        all_users = db.get_session().query(Users).all()
        all_servers = db.get_session().query(Servers).all()
        all_services = db.get_session().query(Services).all()
        joined_objects = []
        for user in all_users:
            current_object = to_json(user)
            del current_object["password"]
            for server in all_servers:
                if server.user_id == user.item_id:
                    current_object = {**current_object, **to_json(server)}
                    for service in all_services:
                        if service.server_id == server.item_id:
                            current_object = {**current_object, **to_json(service)}
                            joined_objects.append(current_object)
        print(joined_objects)

        return joined_objects


class GetCustomersStatisticsHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class UpdateServiceStatusHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        user_id = get_user_id_by_email(incoming_json['email'])
        server = db.get_session().query(Servers).filter(Servers.server_dns == incoming_json['website']).one()
        services = db.get_session().query(Services).filter(Services.server_id == server.item_id).one()
        update_data = incoming_json['update_data']
        update_data_final = {k: 1 if v == 'True' else 0 for k, v in update_data.items()}
        sess = db.get_session()
        sess.query(Services).filter(Services.server_id == server.item_id).update(update_data_final)
        sess.commit()
        sess.close()

        return 1


class AdminUpdateServiceStatusHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        print("admin update**** ")
        print(type(incoming_json['update_data']))
        update_data = incoming_json['update_data']
        sess = db.get_session()
        sess.query(Services).update(update_data)

        sess.commit()
        sess.close()
        return 1


class AddNewWebsiteHandler(Resource):
    """ adding a new website, and its specific protection preferences to an existing client """
    def post(self):
        incoming_json = request.get_json()
        print("adding new website")
        print(incoming_json)
        user_id = get_user_id_by_email(email=incoming_json["email"])
        server = Servers(user_id=user_id,
                        server_ip=incoming_json['services']['ip'],
                        server_dns=incoming_json['services']['website'])
        db.insert(server)
        server_id = server.item_id
        users_services = create_services_object(user_id=user_id, incoming_json=incoming_json,server_id=server_id)
        try:
            db.insert(users_services)
            return 1
        except Exception as e:

            return 0


class UserProtectorHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        host_to_detect = incoming_json['host_name']
        host_to_detect = host_to_detect.replace("http://", "")
        host_to_detect = host_to_detect.replace("https://", "")
        host_to_detect = "https://"+host_to_detect
        print("protecting: "+ host_to_detect)
        response = requests.get(host_to_detect)
        upc = UserProtectionDetector(response)
        resp = upc.detect()
        return {"alerts": resp.security_alerts}


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

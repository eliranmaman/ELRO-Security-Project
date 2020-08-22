import json
import requests
from flask import Flask, request
from flask_restful import Resource, Api
from sqlalchemy.ext.declarative import DeclarativeMeta
from DBAgent.orm import Users, Services, Server
from Detectors import UserProtectionDetector
from Knowledge_Base import log, to_json, LogLevel
from config import db

app = Flask(__name__)
api = Api(app)


class LoginHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        stored_user = db.get_session().query(Users).filter(Users.email == incoming_json['email']).one()
        decrypted_stored_user = db.decrypt(stored_user)
        password = decrypted_stored_user.password

        if password == incoming_json['password']:
            if decrypted_stored_user.is_admin == 1:
                log("[API][LoginHandler] Admin login has occurred: {}".format(incoming_json['email']), LogLevel.INFO)
                return 2
            return 1
        log("[API][LoginHandler] Login Failure has occurred:: {} {}".format(request.remote_addr, incoming_json['email']), LogLevel.INFO, self.post)
        return 0


def get_user_id_by_email(email):
    user = db.get_session().query(Users).filter(Users.email == email).first()
    return user.item_id


def create_services_object(user_id, incoming_json, server_id):
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
        incoming_json = request.get_json()
        log("[API][RegisterHandler] Registering new Client: {}".format(incoming_json['users']['email']), LogLevel.INFO, self.post)
        user = Users(email=incoming_json['users']['email'], password=incoming_json['users']['password'])
        db.insert(user)
        user_id = user.item_id
        server = Server(user_id=user_id,
                         server_ip=incoming_json['services']['ip'],
                         server_dns=incoming_json['services']['website'])
        db.insert(server)
        server_id = server.item_id
        user_services = create_services_object(user_id=user_id, incoming_json=incoming_json, server_id=server_id)
        try:
            db.insert(user_services)
            return 1
        except Exception as e:
            log("[API][RegisterHandler] Error when registering new client, Error: {}".format(e),
                LogLevel.ERROR, self.post)
            return 0


def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj


class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data)  # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields

        return json.JSONEncoder.default(self, obj)


class GetActiveServicesHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        user_id = get_user_id_by_email(email=incoming_json["email"])
        try:
            joined_statuses = []
            all_servers = db.get_session().query(Server).filter(Server.user_id == user_id).all()
            for server in all_servers:
                services = db.get_session().query(Services).filter(Services.server_id == server.item_id).one()
                joined_object = {**to_json(services), **to_json(server)}
                joined_object['website'] = joined_object['server_dns']
                del joined_object['server_dns']
                joined_statuses.append(joined_object)

            return joined_statuses

        except Exception as e:
            log("[API][GetActiveServicesHandler] Exception: {}".format(e), LogLevel.ERROR, self.post)
            return False


class GetUsersDataHandler(Resource):
    def post(self):
        all_users = db.get_session().query(Users).all()
        all_servers = db.get_session().query(Server).all()
        all_services = db.get_session().query(Services).all()
        joined_objects = []
        for user in all_users:
            current_object = to_json(user, to_str=True)
            del current_object["password"]
            for server in all_servers:
                if server.user_id == user.item_id:
                    current_object = {**current_object, **to_json(server)}
                    for service in all_services:
                        if service.server_id == server.item_id:
                            current_object = {**current_object, **to_json(service)}
                            joined_objects.append(current_object)
        log("[API][GetUsersDataHandler] joined_objects: {}".format(joined_objects), LogLevel.DEBUG, self.post)

        return joined_objects


class GetCustomersStatisticsHandler(Resource):
    def post(self):
        return {'bye': 'world'}  # TODO: Royi do we realy need this?!


class UpdateServiceStatusHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        server = db.get_session().query(Server).filter(Server.server_dns == incoming_json['website']).one()
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
        log("[API][AdminUpdateServiceStatusHandler] admin update: {}"
            .format(type(incoming_json['update_data'])), LogLevel.DEBUG, self.post)
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
        user_id = get_user_id_by_email(email=incoming_json["email"])
        server = Server(user_id=user_id,
                        server_ip=incoming_json['services']['ip'],
                        server_dns=incoming_json['services']['website'])
        db.insert(server)
        server_id = server.item_id
        users_services = create_services_object(user_id=user_id, incoming_json=incoming_json,server_id=server_id)
        try:
            db.insert(users_services)
            return 1
        except Exception as e:
            log("[API][AddNewWebsiteHandler] Error when trying to add a new website: {} {}"
                .format(incoming_json['services']['website'], e), LogLevel.ERROR, self.post)
            return 0


class UserProtectorHandler(Resource):
    def post(self):
        incoming_json = request.get_json()
        host_to_detect = incoming_json['host_name']
        host_to_detect = host_to_detect.replace("http://", "")
        host_to_detect = host_to_detect.replace("https://", "")
        host_to_detect = "https://"+host_to_detect
        log("[API][AdminUpdateServiceStatusHandler] getting info with UserProtectionDetector for: {}"
            .format(host_to_detect), LogLevel.INFO, self.post)
        response = requests.get(host_to_detect)
        upc = UserProtectionDetector(response)
        resp = upc.detect(255)
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


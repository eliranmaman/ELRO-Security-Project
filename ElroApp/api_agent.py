from urllib.parse import urlparse
from passlib.handlers.sha2_crypt import sha256_crypt
from functools import wraps
import requests
from flask import Flask, request
from flask_restful import Resource, Api

from DBAgent.orm import Users, Services, Server
from Detectors import UserProtectionDetector
from Knowledge_Base import log, to_json, LogLevel
from config import db, authorized_servers


app = Flask(__name__)
api = Api(app)


services_credentials = ["ip", "website", "sql_detector", "bots_detector", "xss_detector", "xml_detector",
                        "csrf_detector", "cookie_poisoning_detector", "bruteforce_detector"]


def required_authentication(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if request.remote_addr not in authorized_servers:
            return {"msg": "Your not authorized to perform this action", "ip": request.remote_addr, "contact": "contact@elro-sec.com"}
        return func(self, *args, **kwargs)

    return wrapper


def only_json(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not request.is_json():
            return {"msg": "Please send json request.", "ip": request.remote_addr, "contact": "contact@elro-sec.com"}
        if request.get_json() is None:
            return {"msg": "Please send json with the request.", "ip": request.remote_addr, "contact": "contact@elro-sec.com"}
        return func(self, *args, **kwargs)

    return wrapper


class LoginHandler(Resource):

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["email", "password"],
                                   "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][LoginHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        user = db.get_session().query(Users).filter(Users.email == incoming_json['email']).one()
        if user is None:
            log("[API][LoginHandler] Could not locate the {} user: ".format(incoming_json['email']), LogLevel.INFO, self.post)
            return 0
        verify = sha256_crypt.verify(user.password, str(incoming_json['password']))
        if verify:
            if user.is_admin == 1:
                log("[API][LoginHandler] Admin login has occurred: {}".format(incoming_json['email']), LogLevel.INFO)
                return 2
            return 1
        log("[API][LoginHandler] Login Failure has occurred:: {} {}".format(request.remote_addr, incoming_json['email']), LogLevel.INFO, self.post)
        return 0


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


def check_json_object(json_object, credential_list, message):
    return [message.format(field) for field in credential_list if field not in json_object]


class RegisterHandler(Resource):
    """ registers a new client, and his protection preferences """

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["users", "services"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][RegisterHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        errors += check_json_object(incoming_json['users'], ["email", "password"], "Missing {} for the user credentials")
        if len(errors) > 0:
            log("[API][RegisterHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        errors += check_json_object(incoming_json['services'], services_credentials,
                                    message="Missing {} for the services credentials")
        if len(errors) > 0:
            log("[API][RegisterHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        log("[API][RegisterHandler] Registering new Client: {}".format(incoming_json['users']['email']), LogLevel.INFO, self.post)
        user = Users(email=incoming_json['users']['email'],
                     password=sha256_crypt(str(incoming_json['users']['password'])))
        try:
            db.insert(user)
        except Exception as e:
            errors = [str(e)]
        finally:
            if user.item_id is None:
                log("[API][RegisterHandler] Could not insert the user into the database, contact the server "
                    "administrator: {} ".format(errors), LogLevel.INFO, self.post)
                return 0
        server = Server(user_id=user.item_id,
                         server_ip=incoming_json['services']['ip'],
                         server_dns=incoming_json['services']['website'])
        try:
            db.insert(server)
        except Exception as e:
            errors = [str(e)]
        finally:
            if server.item_id is None:
                log("[API][RegisterHandler] Could not insert the server into the database, contact the server "
                    "administrator: {} ".format(errors), LogLevel.INFO, self.post)
                return 0
        user_services = create_services_object(user_id=user.item_id, incoming_json=incoming_json,
                                               server_id=server.item_id)
        try:
            db.insert(user_services)
        except Exception as e:
            errors = [str(e)]
        finally:
            if user_services.item_id is None:
                log("[API][RegisterHandler] Could not insert the services into the database, contact the server "
                    "administrator: {} ".format(errors), LogLevel.INFO, self.post)
                return 0
        return 1


class GetActiveServicesHandler(Resource):

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["email"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][GetActiveServicesHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return False
        user = db.get_session().query(Users).filter(Users.email == incoming_json["email"]).first()
        try:
            joined_statuses = []
            all_servers = db.get_session().query(Server).filter(Server.user_id == user.item_id).all()
            for server in all_servers:
                services = db.get_session().query(Services).filter(Services.server_id == server.item_id).one()
                joined_object = {**to_json(services), **to_json(server)}
                joined_object['website'] = joined_object['server_dns']
                del joined_object['server_dns']
                joined_statuses.append(joined_object)
            log("[API][GetActiveServicesHandler] return {}".format(joined_statuses), LogLevel.DEBUG, self.post)
            return joined_statuses
        except Exception as e:
            log("[API][GetActiveServicesHandler] Exception: {}".format(e), LogLevel.ERROR, self.post)
            return False


class GetUsersDataHandler(Resource):

    @required_authentication
    def post(self):
        # TODO: Royi I don't have any idea what you try to do here.. fix it.
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

    @required_authentication
    def post(self):
        return {'bye': 'world'}  # TODO: Royi do we realy need this?!


class UpdateServiceStatusHandler(Resource):

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["website", "update_data"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][UpdateServiceStatusHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        server = db.get_session().query(Server).filter(Server.server_dns == incoming_json['website']).one()
        if server is None:
            log("[API][UpdateServiceStatusHandler] Could not find the server at the Database: {}"
                .format(incoming_json['website']), LogLevel.INFO, self.post)
            return 0
        update_data = incoming_json['update_data']
        update_data_final = {k: 1 if v == 'True' else 0 for k, v in update_data.items()}
        sess = db.get_session()
        sess.query(Services).filter(Services.server_id == server.item_id).update(update_data_final)
        sess.commit()
        sess.close()
        log("[API][UpdateServiceStatusHandler] Services update successfully for: {}".format(server.server_dns), LogLevel.INFO,
            self.post)
        return 1


class AdminUpdateServiceStatusHandler(Resource):

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["update_data"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][AdminUpdateServiceStatusHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        log("[API][AdminUpdateServiceStatusHandler] admin update: {}"
            .format(type(incoming_json['update_data'])), LogLevel.DEBUG, self.post)
        update_data = incoming_json['update_data']
        sess = db.get_session()
        sess.query(Services).update(update_data)
        sess.commit()
        sess.close()
        log("[API][AdminUpdateServiceStatusHandler] Date updated: {}".format(incoming_json['update_data']),
            LogLevel.DEBUG, self.post)
        return 1


class AddNewWebsiteHandler(Resource):
    """ adding a new website, and its specific protection preferences to an existing client """

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["email", "services"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][AddNewWebsiteHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        errors = check_json_object(incoming_json["services"], services_credentials,
                                   "Could not find {} at the services json object.")
        if len(errors) > 0:
            log("[API][AddNewWebsiteHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        user = db.get_session().query(Users).filter(Users.email == incoming_json["email"]).first()
        if user is None:
            log("[API][AddNewWebsiteHandler] Could not find this user at the datABASE: {}".format(incoming_json["email"]), LogLevel.INFO, self.post)
            return 0
        server = Server(user_id=user.item_id,
                        server_ip=incoming_json['services']['ip'],
                        server_dns=incoming_json['services']['website'])
        try:
            db.insert(server)
        except Exception as e:
            errors = [e]
        finally:
            if server.item_id is None:
                log("[API][RegisterHandler] Could not insert the server into the database, contact the server "
                    "administrator: {} ".format(errors), LogLevel.INFO, self.post)
                return 0
        users_services = create_services_object(user_id=user.item_id, incoming_json=incoming_json, server_id=server.item_id)
        try:
            db.insert(users_services)  # TODO: Royi this is Duplicate code (just copy past from register user)
        except Exception as e:
            errors = [str(e)]
        finally:
            if users_services.item_id is None:
                log("[API][AddNewWebsiteHandler] Could not insert the services into the database, contact the server "
                    "administrator: {} ".format(errors), LogLevel.INFO, self.post)
                return 0
        return 1


class UserProtectorHandler(Resource):

    @required_authentication
    @only_json
    def post(self):
        incoming_json = request.get_json()
        errors = check_json_object(incoming_json, ["host_name"], "Could not find {} at the incoming json object.")
        if len(errors) > 0:
            log("[API][UserProtectorHandler] Could not process the request: {}".format(errors), LogLevel.INFO, self.post)
            return 0
        host_to_detect = urlparse(str(incoming_json['host_name']))
        host_to_detect = '{uri.netloc}'.format(uri=host_to_detect).lower()
        if len(host_to_detect) < 3:
            log("[API][UserProtectorHandler] Could not detect this host: {}".format(host_to_detect), LogLevel.INFO, self.post)
            return 0
        host_to_detect = "https://{}".format(host_to_detect)
        log("[API][UserProtectorHandler] getting info with UserProtectionDetector for: {}"
            .format(host_to_detect), LogLevel.INFO, self.post)
        try:
            response = requests.get(host_to_detect)
        except Exception as e:
            log("[API][UserProtectorHandler] Could not get response: {}".format(e), LogLevel.ERROR, self.post)
            return 0
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


"""
This Class Design to create Relaction maping between the database to the Object Using SQL Alchemy.
Doc: https://docs.sqlalchemy.org/en/13/index.html
Tutorial: https://docs.sqlalchemy.org/en/13/orm/tutorial.html
"""
import datetime
import time

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Float

from DBAgent.sqlalchemy import SQLAlchemy


def to_json(item, ignore_list=None):
    ignore_list = list() if ignore_list is None else ignore_list
    json_data = dict()
    for attr, value in item.__dict__.items():
        if "_sa_instance_state" in attr or attr in ignore_list:
            continue
        json_data[attr] = str(value)

    return json_data


def from_json(json_data, obj):
    for attr, value in json_data.items():
        obj.__dict__[attr] = value
    return obj

class Server(SQLAlchemy.Item):
    __tablename__ = "servers"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    user_id = Column('user_id', Integer, ForeignKey("users.id"), nullable=False)
    server_ip = Column('server_ip', String(1000), unique=True, nullable=False)
    server_dns = Column('server_dns', String(1000), unique=True, nullable=False)
    active = Column('active', Boolean, nullable=False, default=True)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, server_id=None, user_id=None, server_ip=None, server_dns=None, active=None, time_stamp=None):
        self.item_id = server_id
        self.user_id = user_id
        self.server_ip = server_ip
        self.server_dns = server_dns
        self.active = active
        self.time_stamp = time_stamp


class Users(SQLAlchemy.Item):
    __tablename__ = "users"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    email = Column('email', String(1000), unique=True, nullable=False)
    password = Column('password', String(1000), nullable=False)
    active = Column('active', Boolean, nullable=False, default=True)
    registered_on = Column('registered_on', DateTime, nullable=False, default=datetime.datetime.utcnow())
    is_admin = Column('is_admin', Boolean, nullable=False, default=False)
    closed_on = Column('closed_on', DateTime, nullable=True)

    def __init__(self, item_id=None, email=None, password=None, active=None, registered_on=None, is_admin=None,
                 closed_on=None):
        self.item_id = item_id
        self.email = email
        self.password = password
        self.active = active
        self.registered_on = registered_on
        self.is_admin = is_admin
        self.closed_on = closed_on


class Services(SQLAlchemy.Item):
    __tablename__ = "services"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    user_id = Column('user_id', Integer, ForeignKey("users.id"), nullable=False)
    sql_detector = Column('sql_detector', Boolean, nullable=False, default=True)
    bots_detector = Column('bots_detector', Boolean, nullable=False, default=True)
    xss_detector = Column('xss_detector', Boolean, nullable=False, default=True)
    xml_detector = Column('xml_detector', Boolean, nullable=False, default=True)
    csrf_detector = Column('csrf_detector', Boolean, nullable=False, default=True)
    cookie_poisoning_detector = Column('cookie_poisoning_detector', Boolean, nullable=False, default=True)
    bruteforce_detector = Column('bruteforce_detector', Boolean, nullable=False, default=True)
    server_id = Column('server_id', Integer, ForeignKey("servers.id"), unique=True, nullable=False)
    created_on = Column('created_on', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, item_id=None, user_id=None, sql_detector=None, bots_detector=None, xss_detector=None, xml_detector=None,
                 csrf_detector=None, cookie_poisoning_detector=None, bruteforce_detector=None, server_id=None, created_on=None):
        self.item_id = item_id
        self.user_id = user_id
        self.sql_detector = sql_detector
        self.bots_detector = bots_detector
        self.xss_detector = xss_detector
        self.xml_detector = xml_detector
        self.csrf_detector = csrf_detector
        self.cookie_poisoning_detector = cookie_poisoning_detector
        self.bruteforce_detector = bruteforce_detector
        self.server_id = server_id
        self.created_on = created_on


class BlackList(SQLAlchemy.Item):
    __tablename__ = "blacklist"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    ip = Column('password', String(1000), nullable=False)
    server_id = Column('server_id', Integer, ForeignKey("servers.id"), nullable=False)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, item_id=None, ip=None, server_id=None, time_stamp=None):
        self.item_id = item_id
        self.ip = ip
        self.server_id = server_id
        self.time_stamp = time_stamp


class WhiteList(SQLAlchemy.Item):
    __tablename__ = "whitelist"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    ip = Column('password', String(1000), nullable=False)
    server_id = Column('server_id', Integer, ForeignKey("servers.id"), nullable=False)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, item_id=None, ip=None, server_id=None, time_stamp=None):
        self.item_id = item_id
        self.ip = ip
        self.server_id = server_id
        self.time_stamp = time_stamp


# class HttpResponse(SQLAlchemy.Item):
#     __tablename__ = "http_responses"
#     item_id = Column('id', Integer, primary_key=True, unique=True)
#     request_id = Column('request_id', Integer, ForeignKey("http_requests.id"), nullable=False)
#     content = Column('content', String, nullable=False, default='')
#     headers = Column('headers', String, nullable=False, default='')
#     status_code = Column('status_code', Integer, nullable=False)
#     cookies = Column('cookies', String, nullable=False, default='')
#     is_redirect = Column('is_redirect', Boolean, nullable=False)
#     response_url = Column('response_url', String, nullable=False)
#     from_server_id = Column('from_server_id', Integer, ForeignKey("servers.id"), nullable=False)
#     from_dns_name = Column('from_dns_name', String, nullable=False)
#     to_ip = Column('to_ip', String, nullable=False)
#     decision = Column('decision', Boolean, nullable=False)
#     time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)
#
#     def __init__(self, response_id=None, request_id=None, content=None, headers=None, status_code=None, cookies=None,
#                  is_redirect=None, response_url=None, from_server_id=None, to_ip=None, decision=None, time_stamp=None):
#         self.item_id = response_id
#         self.request_id = request_id
#         self.content = content
#         self.headers = headers
#         self.status_code = status_code
#         self.cookies = cookies
#         self.is_redirect = is_redirect
#         self.response_url = response_url
#         self.from_server_id = from_server_id
#         self.to_ip = to_ip
#         self.decision = decision
#         self.time_stamp = time_stamp


# class HttpRequest(SQLAlchemy.Item):
#     __tablename__ = "http_requests"
#     item_id = Column('id', Integer, primary_key=True, unique=True)
#     response_id = Column('response_id', Integer, nullable=True)
#     method = Column('method', String, nullable=False)
#     content = Column('content', String, nullable=False, default='')
#     headers = Column('headers', String, nullable=False, default='')
#     path = Column('path', String, nullable=False, default='/')
#     to_server_id = Column('to_server_id', Integer, ForeignKey("servers.id"), nullable=False)
#     host_name = Column('host_name', String, nullable=False)
#     from_ip = Column('from_ip', String, nullable=False)
#     decision = Column('decision', Boolean, nullable=False)
#     time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)
#
#     def __init__(self, request_id=None, response_id=None, method=None, content=None, headers=None, path=None,
#                  host_name=None, to_server_id=None, from_ip=None, decision=None, time_stamp=None):
#         self.item_id = request_id
#         self.response_id = response_id
#         self.method = method
#         self.content = content
#         self.headers = headers
#         self.path = path
#         self.host_name = host_name
#         self.from_ip = from_ip
#         self.to_server_id = to_server_id
#         self.decision = decision
#         self.time_stamp = time_stamp


class DetectorRequestData(SQLAlchemy.Item):
    __tablename__ = "detectors_requests_data"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    detected = Column('detected', String, nullable=False, default="none")
    to_server_id = Column('to_server_id', Integer, ForeignKey("servers.id"), nullable=False)
    from_ip = Column('from_ip', String, nullable=False)

    def __init__(self, item_id=None, detected=None, to_server_id=None, from_ip=None):
        self.item_id = item_id
        self.detected = detected
        self.to_server_id = to_server_id
        self.from_ip = from_ip


class DetectorDataResponse(SQLAlchemy.Item):
    __tablename__ = "detectors_data_responses"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("detectors_requests_data.id"), nullable=False)
    detected = Column('detected', String, nullable=False, default="none")
    from_server_id = Column('from_server_id', Integer, ForeignKey("servers.id"), nullable=False)
    to_ip = Column('to_ip', String, nullable=False)

    def __init__(self, item_id=None, request_id=None, detected=None, from_server_id=None, to_ip=None):
        self.item_id = item_id
        self.request_id = request_id
        self.detected = detected
        self.from_server_id = from_server_id
        self.to_ip = to_ip


class CookiesToken(SQLAlchemy.Item):
    __tablename__ = "cookie_token"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    dns_name = Column('dns_name', String, nullable=False)
    ip = Column('ip', String, nullable=False)
    token = Column('token', String, nullable=False)
    active = Column('active', Boolean, nullable=False, default=True)

    def __init__(self, item_id=None, dns_name=None, ip=None, token=None, active=True):
        self.item_id = item_id
        self.dns_name = dns_name
        self.ip = ip
        self.token = token
        self.active = active


class BruteForceDataItem(SQLAlchemy.Item):
    __tablename__ = "brute_force_data"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    dns_name = Column('dns_name', String, nullable=False)
    ip = Column('ip', String, nullable=False)
    path = Column('token', String, nullable=False)
    counter = Column('counter', Integer, default=0, nullable=False)
    time_stamp = Column('time_stamp', Integer, nullable=False, default=time.time())

    def __init__(self, item_id=None, dns_name=None, ip=None, path=None, counter=0, time_stamp=time.time()):
        self.item_id = item_id
        self.dns_name = dns_name
        self.ip = ip
        self.path = path
        self.counter = counter
        self.time_stamp = time_stamp

"""
This Class Design to create Relation mapping between the database to the Object Using SQL Alchemy.
Doc: https://docs.sqlalchemy.org/en/13/index.html
Tutorial: https://docs.sqlalchemy.org/en/13/orm/tutorial.html
"""
import datetime
import time
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Float

from DBAgent.sqlalchemy import SQLAlchemy


# This table will contain all the servers of the users
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


# This table will contain all the users
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


# This table will contain all the configurations of the detectors for each user
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

    def __init__(self, item_id=None, user_id=None, sql_detector=None, bots_detector=None, xss_detector=None,
                 xml_detector=None,
                 csrf_detector=None, cookie_poisoning_detector=None, bruteforce_detector=None, server_id=None,
                 created_on=None):
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


# This table will contain the servers that we will automatically block requests to
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


# This table will contain the servers that we will automatically not check requests to
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


# This table will contain the history of all the requests that arrived to Elro
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


# This table will contain the history of all the responses that arrived through Elro
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


# This table will contain all the cookies token's of the requests that arrived to Elro
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


# This table will contain all the info needed to detected brute-force attempt
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

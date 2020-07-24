"""
This Class Design to create Relation mapping between the database to the Object Using SQL Alchemy.
Doc: https://docs.sqlalchemy.org/en/13/index.html
Tutorial: https://docs.sqlalchemy.org/en/13/orm/tutorial.html
"""
import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Float

from DBAgent.sqlalchemy import SQLAlchemy


class Server(SQLAlchemy.Item):
    __tablename__ = "servers"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    customer_id = Column('customer_id', Integer, ForeignKey("customers.id"), nullable=False)
    server_ip = Column('server_ip', String, unique=True, nullable=False)
    server_dns = Column('server_dns', String, unique=True, nullable=False)
    active = Column('active', Boolean, nullable=False, default=True)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, server_id=None, customer_id=None, server_ip=None, server_dns=None, active=None, time_stamp=None):
        self.item_id = server_id
        self.customer_id = customer_id
        self.server_ip = server_ip
        self.server_dns = server_dns
        self.active = active
        self.time_stamp = time_stamp


class Users(SQLAlchemy.Item):
    __tablename__ = "users"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    email = Column('email', String, unique=True, nullable=False)
    password = Column('password', String, nullable=False)
    active = Column('active', Boolean, nullable=False, default=True)
    registered_on = Column('registered_on', DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_admin = Column('is_admin', Boolean, nullable=False, default=True)
    closed_on = Column('closed_on', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, item_id=None, email=None, password=None, active=None, registered_on=None, is_admin=None,
                 closed_on=None):
        self.item_id = item_id
        self.email = email
        self.password = password
        self.active = active
        self.registered_on = registered_on
        self.is_admin = is_admin
        self.closed_on = closed_on


class BlackList(SQLAlchemy.Item):
    __tablename__ = "blacklist"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    ip = Column('password', String, nullable=False)
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
    ip = Column('password', String, nullable=False)
    server_id = Column('server_id', Integer, ForeignKey("servers.id"), nullable=False)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, item_id=None, ip=None, server_id=None, time_stamp=None):
        self.item_id = item_id
        self.ip = ip
        self.server_id = server_id
        self.time_stamp = time_stamp


class HttpResponse(SQLAlchemy.Item):
    __tablename__ = "http_responses"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("http_requests.id"), nullable=False)
    method = Column('method', String, nullable=False)
    content = Column('content', String, nullable=True)
    from_server_id = Column('from_server_id', Integer, ForeignKey("servers.id"), nullable=False)
    to_ip = Column('to_ip', String, nullable=False)
    decision = Column('decision', Boolean, nullable=False)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, response_id=None, request_id=None, method=None, content=None, from_server_id=None, to_ip=None,
                 decision=None, time_stamp=None):
        self.item_id = response_id
        self.request_id = request_id
        self.method = method
        self.content = content
        self.from_server_id = from_server_id
        self.to_ip = to_ip
        self.decision = decision
        self.time_stamp = time_stamp


class HttpRequest(SQLAlchemy.Item):
    __tablename__ = "http_requests"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    response_id = Column('response_id', Integer, ForeignKey("http_responses.id"), nullable=False)
    method = Column('method', String, nullable=False)
    content = Column('content', String, nullable=True)
    to_server_id = Column('to_server_id', Integer, ForeignKey("servers.id"), nullable=False)
    from_ip = Column('from_ip', String, nullable=False)
    decision = Column('decision', Boolean, nullable=False)
    time_stamp = Column('time_stamp', DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __init__(self, request_id=None, response_id=None, method=None, content=None, to_server_id=None, from_ip=None,
                 decision=None, time_stamp=None):
        self.item_id = request_id
        self.response_id = response_id
        self.method = method
        self.content = content
        self.from_ip = from_ip
        self.to_server_id = to_server_id
        self.decision = decision
        self.time_stamp = time_stamp


class DetectorRequestData(SQLAlchemy.Item):
    __tablename__ = "detectors_requests_data"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("http_requests.id"), nullable=False)
    bruteforce = Column('bruteforce', Boolean, nullable=False)
    bots = Column('bots', Boolean, nullable=False)
    cookie_poisoning = Column('cookie_poisoning', Boolean, nullable=False)
    csrf = Column('csrf', Boolean, nullable=False)
    ddos = Column('ddos', Boolean, nullable=False)
    sql_injection = Column('sql_injection', Boolean, nullable=False)
    xml_injection = Column('xml_injection', Boolean, nullable=False)
    xss_injection = Column('xss_injection', Boolean, nullable=False)

    def __init__(self, item_id=None, request_id=None, bruteforce=None, bots=None, cookie_poisoning=None, csrf=None,
                 ddos=None, sql_injection=None, xml_injection=None, xss_injection=None):
        self.item_id = item_id
        self.request_id = request_id
        self.bruteforce = bruteforce
        self.bots = bots
        self.cookie_poisoning = cookie_poisoning
        self.csrf = csrf
        self.ddos = ddos
        self.sql_injection = sql_injection
        self.xml_injection = xml_injection
        self.xss_injection = xss_injection


class MLRequestData(SQLAlchemy.Item):
    __tablename__ = "ml_requests_data"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("http_requests.id"), nullable=False)
    bruteforce = Column('bruteforce', Float, nullable=False)
    bots = Column('bots', Float, nullable=False)
    cookie_poisoning = Column('cookie_poisoning', Float, nullable=False)
    csrf = Column('csrf', Float, nullable=False)
    ddos = Column('ddos', Float, nullable=False)
    sql_injection = Column('sql_injection', Float, nullable=False)
    xml_injection = Column('xml_injection', Float, nullable=False)
    xss_injection = Column('xss_injection', Float, nullable=False)

    def __init__(self, item_id=None, request_id=None, bruteforce=None, bots=None, cookie_poisoning=None, csrf=None,
                 ddos=None, sql_injection=None, xml_injection=None, xss_injection=None):
        self.item_id = item_id
        self.request_id = request_id
        self.bruteforce = bruteforce
        self.bots = bots
        self.cookie_poisoning = cookie_poisoning
        self.csrf = csrf
        self.ddos = ddos
        self.sql_injection = sql_injection
        self.xml_injection = xml_injection
        self.xss_injection = xss_injection


class DetectorDataResponse(SQLAlchemy.Item):
    __tablename__ = "detectors_data_responses"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("http_responses.id"), nullable=False)
    user_protection = Column('bruteforce', Boolean, nullable=False)
    xss_injection = Column('bots', Boolean, nullable=False)

    def __init__(self, item_id=None, response_id=None, user_protection=None, xss_injection=None):
        self.item_id = item_id
        self.response_id = response_id
        self.user_protection = user_protection
        self.xss_injection = xss_injection


class MLDataResponse(SQLAlchemy.Item):
    __tablename__ = "ml_data_responses"
    item_id = Column('id', Integer, primary_key=True, unique=True)
    request_id = Column('request_id', Integer, ForeignKey("http_responses.id"), nullable=False)
    user_protection = Column('bruteforce', Float, nullable=False)
    xss_injection = Column('bots', Float, nullable=False)

    def __init__(self, item_id=None, response_id=None, user_protection=None, xss_injection=None):
        self.item_id = item_id
        self.response_id = response_id
        self.user_protection = user_protection
        self.xss_injection = xss_injection
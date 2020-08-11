"""
Crypto issue: https://github.com/openthread/openthread/issues/1137
Varname: https://github.com/pwwang/python-varname
"""
from functools import wraps
from cryptography.fernet import Fernet

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from DBAgent import DBHandler

enc_list = ["content", "headers", "cookies", "password"]
enc_key = b'tkBV4rY7gcEoWmpvqHZTvXExvuh8YsfhcdFUdBPzXeU='


def encrypt_data(value):
    cipher_suite = Fernet(enc_key)
    cipher_text = cipher_suite.encrypt(value.encode('utf-8'))
    print(cipher_text.decode('utf-8'))
    return cipher_text.decode('utf-8')


def decrypt_data(value):
    value = value.encode('utf-8')
    cipher_suite = Fernet(enc_key)
    plain_text = cipher_suite.decrypt(value)
    return plain_text.decode('utf-8')


def encrypt_item(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        for var in args:
            for attr, value in var.__dict__.items():
                if attr in enc_list:
                    var.__dict__[attr] = encrypt_data(value)
            func(self, *args, **kwargs)
    return wrapper


def decrypt_item(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        item = func(self, *args, **kwargs)
        for attr, value in item.__dict__.items():
            if attr in enc_list:
                item.__dict__[attr] = decrypt_data(value)
        return item
    return wrapper


class SQLAlchemy(DBHandler):

    Item = declarative_base()

    def __init__(self, user, password, host, port, database):
        super().__init__(user, password, host, port, database)
        # self.__engine = create_engine("postgresql+psycopg2://{}:{}@{}:{}/{}".
        #                               format(self._user, self._password, self._host, self._port, self._database))
        self.__engine = create_engine("mysql+pymysql://{}:{}@{}:{}/{}".
                                      format(self._user, self._password, self._host, self._port, self._database))
        self._session = sessionmaker(bind=self.__engine)()

    def connect(self):
        """
        This function will create the connection for the database
        (in case it is not connected already & create the relevant tables if not exists)
        :return: None
        """
        if self._connection is None:
            self._connection = self.__engine.connect()
            print("[DATABASE] {} Connected.".format(self._database))
            print("[DATABASE] Creating Tables....")
            self.Item.metadata.create_all(self.__engine)
            print("[DATABASE] Creation completed.")

    def close(self):
        """
        This method closing existing session and database connection.
        Be Aware: !!! THIS METHOD DO NOT MAKE COMMIT BEFORE CLOSING THE CONNECTION !!!
        :return: None
        """
        if self._session is not None:
            self._session.close_all()
        if self._connection is not None:
            self._connection.close()
        self._session = None
        self._connection = None

    def get_session(self):
        self._session = sessionmaker(bind=self.__engine)()
        return self._session

    def commit(self):
        if self._session is None:
            return
        try:
            self._session.commit()
        except Exception as e:
            self._session.rollback()

    @encrypt_item
    def add(self, item):
        if self._session is None:
            return
        try:
            self._session.add(item)
        except Exception as e:
            self._session.rollback()

    @encrypt_item
    def insert(self, item):
        if self._session is None:
            return False
        try:
            self._session.add(item)
            self.commit()
        except Exception as e:
            self._session.rollback()

    @decrypt_item
    def decrypt(self, item):
        return item

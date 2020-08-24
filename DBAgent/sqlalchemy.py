"""
Crypto issue: https://github.com/openthread/openthread/issues/1137
Varname: https://github.com/pwwang/python-varname
"""
import json
from functools import wraps
from http.client import HTTPMessage

from cryptography.fernet import Fernet

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from DBAgent import DBHandler


class SQLAlchemy(DBHandler):

    Item = declarative_base()

    def __init__(self, user, password, host, port, database):
        super().__init__(user, password, host, port, database)
        self.__engine = create_engine("postgresql+psycopg2://{}:{}@{}:{}/{}".
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
        return self._session

    def commit(self):
        if self._session is None:
            return
        self._session.commit()
        self._session = sessionmaker(bind=self.__engine)()

    def add(self, item):
        self._session.add(item)

    def insert(self, item):
        if self._session is None:
            return False
        for attr, value in item.__dict__.items():
            if type(value) is HTTPMessage:
                item.__dict__[attr] = value.as_string()
        _session = sessionmaker(bind=self.__engine)()
        _session.add(item)
        _session.commit()

    def decrypt(self, item):
        return item

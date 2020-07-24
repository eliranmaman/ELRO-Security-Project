"""
Crypto issue: https://github.com/openthread/openthread/issues/1137
Varname: https://github.com/pwwang/python-varname
"""
import json
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from varname import nameof

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from DBAgent import DBHandler
from config import enc_key, enc_list


def encrypt_data(value):
    value = json.dumps(value) if type(value) is dict else value
    key = SHA256.new(enc_key).digest()
    enc_IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, enc_IV)
    enc_padding = AES.block_size - len(value) % AES.block_size
    value += bytes([enc_padding]) * enc_padding
    value = enc_IV + encryptor.encrypt(value)
    return value


def decrypt_data(value):
    key = SHA256.new(enc_key).digest()
    dec_IV = value[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, dec_IV)
    value = decryptor.decrypt(value[AES.block_size:])
    dec_padding = value[-1]
    value = value[:-dec_padding]
    return value


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

    @encrypt_item
    def add(self, item):
        self._session.add(item)

    @encrypt_item
    def insert(self, item):
        if self._session is None:
            return False
        self._session.add(item)
        self.commit()

    @decrypt_item
    def decrypt(self, item):
        return item

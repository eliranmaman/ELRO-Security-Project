
class DBHandler(object):

    def __init__(self, user, password, host, port, database):
        self._connection = None
        self._user, self._password, self._host, self._port, self._database = user, password, host, port, database

    def connect(self):
        """
        This function will create the connection for the database.
        :return: Boolean
        """
        raise NotImplementedError()

    def close(self):
        """
        This function will close the connection with the database.
        :return:
        """
        raise NotImplementedError()

    def get_session(self):
        """
        This function will return cursor for active connection (or session).
        :return: cursor or session
        """
        raise NotImplementedError()

    def commit(self):
        """
        This function will do commit for active connection (session).
        :return:
        """
        raise NotImplementedError()

    def insert(self, item):
        """
        Add new item from the ORM to the database. Please note: This function should insert & make commit also.
        :param item: The item to insert
        :return: None
        """
        raise NotImplementedError()

    def add(self, item):
        """
        Add new item from the ORM to the database. Please note: This function will not make commit,
        only added for the current session.
        :param item: The item to add
        :return: None
        """
        raise NotImplementedError()

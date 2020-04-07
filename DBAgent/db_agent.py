
class DBHandler(object):

    def __init__(self, user, password, host, port, database):
        self.__connection = None
        self.__user, self.__password, self.__host, self.__port, self.__database = user, password, host, port, database

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

    def get_cursor(self):
        """
        This function will return cursor for active connection.
        :return: cursor
        """
        raise NotImplementedError()

    def commit(self):
        """
        This function will do commit for active connection.
        :return:
        """
        raise NotImplementedError()
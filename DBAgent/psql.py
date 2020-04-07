import psycopg2
from DBAgent import DBHandler


class PsqlHandler(DBHandler):

    def __init__(self, user, password, host, port, database):
        super().__init__(user, password, host, port, database)

    def connect(self):
        try:
            self.__connection = psycopg2.connect(user=self.__user, password=self.__password, host=self.__host,
                                          port=self.__port, database=self.__database)
            print("Database is online..")
            print("\tCreating tables if not existing ...")
            print("Done.")
        except (Exception, psycopg2.Error) as error:
            print("\tError while connecting to PostgreSQL", error)

    def close(self):
        # closing database connection.
        if self.__connection:
            self.__connection.close()
            print("PostgreSQL connection is closed")

    def get_cursor(self):
        return self.__connection.cursor(cursor_factory = psycopg2.extras.RealDictCursor)



import psycopg2
from DBAgent import DBHandler


class PSQLHandler(DBHandler):

    def __init__(self, user, password, host, port, database):
        super().__init__(user, password, host, port, database)

    def connect(self):
        try:
            self._connection = psycopg2.connect(user=self._user, password=self._password, host=self._host,
                                                 port=self._port, database=self._database)
            print("Database is online..")
            print("\tCreating tables if not existing ...")
            print("Done.")
        except (Exception, psycopg2.Error) as error:
            print("\tError while connecting to PostgreSQL", error)

    def close(self):
        # closing database connection.
        if self._connection:
            self._connection.close()
            print("PostgreSQL connection is closed")

    def get_session(self):
        return self._connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def commit(self):
        self._connection.commit()

    def insert(self, item):
        raise NotImplementedError()

    def add(self, item):
        raise NotImplementedError()

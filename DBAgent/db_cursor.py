from DBAgent import Items


class DBCursor(object):

    def __init__(self, db_agent):
        """
        This method will handle the communication with the database,
         will be responsible for all the queries.
        :param db_agent: The db agent connection
        """
        self._db_agent = db_agent
        self.database_map = {}

    def get_servers_item(self):
        pass
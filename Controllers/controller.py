

class Controller(object):

    def __init__(self, parser, detectors):
        self._parser = None  # will work on the same threads.
        self._detectors = dict()  # dict of detectors available for the Controller.
        self._db = None  # will hold the Database connection.
        raise NotImplementedError()

    def activate(self, request):
        """
        This function will handler all the system logic. Including activate the parser, detectors, etc.
        :param request: The request that arrived from the Proxy.
        :return: HTTP response
        """

    def _parse(self):
        """
        This function will be responsible to activate the parser.
        :return: dict, with the parsed data.
        """

    def _is_authorized(self, server_ip, requester_ip):
        """
        This function will check if the request is authorized in terms of:
            1) The requester isn't in the server black list.
        :param server_ip: will hold the server ip
        :param requester_ip: will hold the requester ip
        :return: Boolean (True for yes, False for no)
        """

    def _list_of_detectors(self, server_ip):
        """
        This function will return a list of relevant detectors for the server.
        e.g: Server has the SQL_inj And XSS_inj Protection => ['SQLinj', 'XSSinj']
        :param server_ip: will hold the Server ip
        :return: list (of Detectors Enum)
        """

    def _extra_data(self, server_ip):
        """
        This function will return a dict that contain an extra data (for filtering purpose)
        About the server (forbidden words list & legitimate words list). In case of conflict will
        resolve in the detector implementation.
        :param server_ip: The server ip.
        :return: dict ('legitimate': list, 'forbidden': list)
        """

    def _run_query(self, query):
        """
        This function will update the DB with new information (e.g: response detectors data)
        :param update_query: Will hold a string of the query
        :return: None
        """
        cursor = self._db.get_cursor()
        try:
            cursor.execute(query)
        finally:
            self._db.commit()
            cursor.close()
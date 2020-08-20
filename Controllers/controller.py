

class Controller(object):

    def __init__(self, detectors):
        self._detectors = detectors  # dict of detectors available for the Controller.
        self._db = None  # will hold the Database connection.

    def request_handler(self, request, original_request):
        """
        This function will handler all the system logic. Including activate the parser, detectors, etc.
        :param original_request:
        :param request: The request that arrived from the Proxy.
        :return: HTTP response
        """
        raise NotImplementedError()

    def response_handler(self, request, original_response):
        """
        This function will handler all the system logic. Including activate the parser, detectors, etc.
        :param original_response:
        :param request: The request that arrived from the Proxy.
        :return: HTTP response
        """
        raise NotImplementedError()

    def _is_authorized(self, requester_ip):
        """
        This function will check if the request is authorized in terms of:
            1) The requester isn't in the server black list.
        :param server_ip: will hold the server ip
        :param requester_ip: will hold the requester ip
        :return: Boolean (True for yes, False for no)
        """
        raise NotImplementedError()

    def _list_of_detectors(self, server_ip):
        """
        This function will return a list of relevant detectors for the server.
        e.g: Server has the SQL_inj And XSS_inj Protection => ['SQLinj', 'XSSinj']
        :param server_ip: will hold the Server ip
        :return: list (of Detectors Enum)
        """
        raise NotImplementedError()

    def _extra_data(self, server_ip):
        """
        This function will return a dict that contain an extra data (for filtering purpose)
        About the server (forbidden words list & legitimate words list). In case of conflict will
        resolve in the detector implementation.
        :param server_ip: The server ip.
        :return: dict ('legitimate': list, 'forbidden': list)
        """
        raise NotImplementedError()
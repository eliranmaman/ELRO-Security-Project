import enum


class Parser(object):

    class Protocol(enum.Enum):
        HTTP_req = "http_request"
        HTTP_res = "http_response"
        HTTPS_req = "https_request"
        HTTPS_res = "https_response"
        FTP = "ftp"

    def __init__(self, protocol=Protocol.HTTP_req):
        """
        :param protocol: The type of the data that this parser can handle with.
        """
        self.protocol = protocol

    def parse(self, data_to_parse):
        """
        This method will parse the data.
        :return: a dict of the parsed data
        """
        raise NotImplementedError()

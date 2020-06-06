import enum


class Parser(object):

    class DataType(enum.Enum):
        Request = 1,
        Response = 2

    def parse(self, data, data_type):
        """
        This method will parse the data.
        :data: the request / response
        :data_type: Enum of DataType to identify.
        :return: Dict
        """
        raise NotImplementedError()

    def _parse_request(self, data):
        raise NotImplementedError()

    def _parse_response(self, data):
        raise NotImplementedError()


class BaseHTTPRequestParser(Parser):

    def parse(self, data, data_type):
        """
        :param data:
        :param data_type:
        :return:
        """
        parsed_data = dict()

    def _parse_request(self, data):
        parsed_data = dict()
        parsed_data["client_ip"] = data.client_address[0]
        parsed_data["headers"] = data.headers
        parsed_data["method"] = "{}".format(data.method).upper()
        parsed_data["path"] = "{}".format(data.path)

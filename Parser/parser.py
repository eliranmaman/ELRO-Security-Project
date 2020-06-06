import enum


class Parser(object):

    class DataType(enum.Enum):
        Request = 1,
        Response = 2

    def parse(self, data, data_type, method):
        """
        This method will parse the data.
        :data: the request / response
        :method: the request / response method (e.g GET)
        :data_type: Enum of DataType to identify.
        :return: Dict
        """
        raise NotImplementedError()

    def _parse_request(self, data, method):
        """
        This method will parse requests.
        :param data: The request
        :param method: The request method (e.g GET)
        :return: dict
        """
        raise NotImplementedError()

    def _parse_response(self, data):
        """
        This method will parse response.
        :param data: The request
        :return: dict
        :return: dict
        """
        raise NotImplementedError()


class BaseHTTPRequestParser(Parser):

    def _parse_response(self, data):
        pass

    def parse(self, data, data_type, method):
        return self._parse_request(data, method)

    def _parse_request(self, data, method):
        parsed_data = dict()
        parsed_data["client_ip"] = data.client_address[0]
        parsed_data["headers"] = data.headers
        parsed_data["method"] = "{}".format(method).upper()
        parsed_data["path"] = "{}".format(data.path)
        parsed_data["Content-Length"] = int(data.headers.get('Content-Length', 0))
        parsed_data["body"] = data.rfile.read(parsed_data["Content-Length"])
        parsed_data["rfile"] = data.rfile
        return parsed_data

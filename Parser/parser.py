from datetime import datetime


class HttpResponse(object):

    def __init__(self, request_id=None, content=None, headers=None, status_code=None, cookies=None, original=None,
                 is_redirect=None, response_url=None, from_server_id=None, to_ip=None, decision=None, time_stamp=None):
        self.original = original
        self.request_id = request_id
        self.content = content
        self.headers = headers
        self.status_code = status_code
        self.cookies = cookies
        self.is_redirect = is_redirect
        self.response_url = response_url
        self.from_server_id = from_server_id
        self.to_ip = to_ip
        self.decision = decision
        self.time_stamp = time_stamp


class HttpRequest(object):

    def __init__(self, method=None, content=None, headers=None, path=None,
                 host_name=None, to_server_id=None, from_ip=None, decision=None, time_stamp=None):
        self.method = method
        self.content = content
        self.headers = headers
        self.path = path
        self.host_name = host_name
        self.from_ip = from_ip
        self.to_server_id = to_server_id
        self.decision = decision
        self.time_stamp = time_stamp
        self.text = None


class Parser(object):

    def parse(self, data_to_parse):
        """
        This method will parse the data.
        :data: the request / response
        :method: the request / response method (e.g GET)
        :data_type: Enum of DataType to identify.
        :return: ORM HttpRequest/HttpResponse Object
        """
        raise NotImplementedError()


class BaseHTTPRequestParser(Parser):

    def parse(self, data_to_parse):
        parsed_data = HttpRequest()
        parsed_data.method = "{}".format(data_to_parse.command).upper()
        content_length = int(data_to_parse.headers.get('Content-Length', 0))
        parsed_data.content = data_to_parse.rfile.read(content_length)
        parsed_data.headers = data_to_parse.headers
        parsed_data.path = "{}".format(data_to_parse.path)
        parsed_data.host_name = "{}".format(data_to_parse.headers.get('HOST')).replace("www.", "")\
            .replace("https://", "").replace("http", "")
        parsed_data.from_ip = data_to_parse.client_address[0]
        parsed_data.time_stamp = data_to_parse.log_date_time_string()
        return parsed_data


class HTTPResponseParser(Parser):

    def __init__(self, request):
        """
        :param request: The original request
        """
        self.__request = request

    def parse(self, data_to_parse):
        parsed_data = HttpResponse()
        parsed_data.original = data_to_parse
        parsed_data.text = data_to_parse.text
        parsed_data.content = data_to_parse.text
        parsed_data.headers = data_to_parse.headers
        parsed_data.status_code = data_to_parse.status_code
        parsed_data.cookies = data_to_parse.cookies
        parsed_data.is_redirect = data_to_parse.is_redirect
        parsed_data.response_url = data_to_parse.url
        parsed_data.from_server_id = self.__request.to_server_id
        parsed_data.to_ip = self.__request.from_ip
        parsed_data.time_stamp = datetime.now()
        parsed_data.from_dns_name = self.__request.host_name
        return parsed_data

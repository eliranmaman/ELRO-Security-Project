from requests import Response


class HTTPSEnforcer(object):

    def is_connection_secure(self, request):
        raise NotImplementedError()

    def enforce(self, request):
        raise NotImplementedError()


class HSTS(HTTPSEnforcer):

    def is_connection_secure(self, request):
        pass

    def enforce(self, request):
        """
        We will generate new response with HSTS header, and send it to the client.
        :param request: The request
        :return: None
        """
        response = Response()
        response.status_code = 403
        response.code = "Forbidden"
        response._content = ""
        response.error_type = "Forbidden"
        response.headers = {'Strict-Transport-Security': "max-age=15552000; preload"}
        request.send_response(response.status_code)
        request.send_resp_headers(response)

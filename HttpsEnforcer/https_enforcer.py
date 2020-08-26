from requests import Response


class HTTPSEnforcer(object):

    def is_connection_secure(self, request):
        raise NotImplementedError()

    def enforce(self, request):
        raise NotImplementedError()


class HSTS(HTTPSEnforcer):

    def enforce(self, request_url):
        """
        We will generate new response with HSTS header, and send it to the client.
        :param request_url: The request url (str)
        :return: dict
        """
        headers = {
            'Strict-Transport-Security': "max-age=15552000; preload",
            "Location": "https://{}"
                .format(request_url.replace("http://", "").replace("www.", "").replace("https://", ""))
        }
        return headers

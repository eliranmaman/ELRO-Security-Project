"""
TODO: Information, Tests.
"""
import math
import re
from functools import wraps
from urllib.parse import urlparse

from config import bit_map, url_regex, bit_map_errors

map_bit = bit_map


def invoke_detector(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if is_on(map_bit[func.__name__], self.bit_indicator):
            is_detected = func(self, *args, **kwargs)
            print(func.__name__, "Is detected:", is_detected)
            if is_detected:
                self._UserProtectionResults.bit_map |= map_bit[func.__name__]
                self._UserProtectionResults.detected_alerts.append(bit_map_errors[map_bit[func.__name__]])
    return wrapper


class UserProtectionResults(object):

    def __init__(self):
        self.bit_map = 0
        self.csrf_urls = []
        self.csrf_js_files = False
        self.detected_alerts = []
        self.name = "user_protection"


def is_on(index, bit):
    if index == 0:
        return 0
    if index == 1:
        return bit % 2 == 1
    index = int(math.log(index) / math.log(2))
    return (bit >> index) % 2


class UserProtectionDetector(object):

    def __init__(self, response):
        """
        :param response: The original Response
        """
        self._UserProtectionResults = UserProtectionResults()
        self._response = response
        self.bit_indicator = 0

    def detect(self, bit_indicator):
        """
        The method is the user interface for this class
        :return: UserProtectionResults Object.
        """
        self.bit_indicator = bit_indicator
        print("{0:b}".format(bit_indicator))
        self.__detect_csrf_requests()
        self.__detect_script_files()
        self.__access_cookies()
        self.__iframe()
        self.__detect_inline_scripts()
        return self._UserProtectionResults

    @invoke_detector
    def __detect_inline_scripts(self):
        """
        Will looking for inline scripts in the page.
        :return: Boolean
        """
        return self._response.text.find("<script") > 0

    @invoke_detector
    def __detect_script_files(self):
        """
        This method will look for attempt to load js files from other origins, It is not give as
        100% insurance but, it is better from nothing. It is important that this method will activate after
        "__detect_csrf_requests"
        :return: Boolean
        """
        return self._response.headers.get('Content-Type', "").find(
            "javascript") > 0 or self._UserProtectionResults.csrf_js_files or self._response.text.find(".js\"") > 0 \
            or self._response.text.find("<script src=\"") > 0 or self._response.text.find("\"></script>") > 0

    @invoke_detector
    def __access_cookies(self):
        """
        This method will try to detect attempt to access the user cookies via the DOM
        :return: Boolean
        """
        return self._response.text.find("document.cookie") > 0 or self._response.text.find("browser.cookie") > 0

    @invoke_detector
    def __iframe(self):
        """
        This method will try to detect if the page is trying to load another page in iframe.
        This method has high value of False Positive.
        :return: Boolean
        """
        return self._response.text.find("iframe") > 0

    @invoke_detector
    def __detect_csrf_requests(self):
        """
        This method will try to detect if the page is trying to invoke Cross Site
        Requests (CSRF), images, scripts and other are include.
        This method has high value of False Positive.
        :return: Boolean
        """
        response_url = urlparse(self._response.response_url)
        response_url = '{uri.netloc}'.format(uri=response_url).replace("www.", "")
        urls = re.findall(url_regex, self._response.text)
        for url in urls:
            url = url[0]
            parsed_uri = urlparse(url)
            if not self._UserProtectionResults.csrf_js_files:
                self._UserProtectionResults.csrf_js_files = '{uri.path}'.format(uri=parsed_uri).find('.js') > 0
            host_uri = '{uri.netloc}'.format(uri=parsed_uri).replace("www.", "")
            if response_url != host_uri:
                self._UserProtectionResults.csrf_urls.append((host_uri, url))
        return len(self._UserProtectionResults.csrf_urls) > 0

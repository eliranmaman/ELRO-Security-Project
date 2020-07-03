from UserProtection.user_protection import UPDetector
from config import bit_map


class ScriptDetector(UPDetector):

    def __init__(self):
        self.__bit_map = 0

    def detect(self, response):
        self.__detect_inline_scripts(response)
        self.__detect_script_files(response)
        self.__access_cookies(response)
        self.__iframe(response)
        return self.__bit_map

    def __detect_inline_scripts(self, response):
        if response.text.find("script") > 0:
            self.__bit_map = self.__bit_map | bit_map["inline_script"]

    def __detect_script_files(self, response):
        if response.headers.get('Content-Type', "").find("javascript") > 0:
            self.__bit_map = self.__bit_map | bit_map["files_script"]

    def __access_cookies(self, response):
        if response.text.find("document.cookie") > 0:
            self.__bit_map = self.__bit_map | bit_map["access_cookies"]

    def __iframe(self, response):
        if response.text.find("iframe") > 0:
            self.__bit_map = self.__bit_map | bit_map["iframe"]




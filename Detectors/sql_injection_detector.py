import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class SqlInjection(Detector):

    __Forbidden_FILE = data_path+"/Detectors/wwwww/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.__flag = list()
        self.refresh()

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        # request = str(request).upper()
        request = re.escape(request)
        print(request)
        flags = []
        print("Strart Regular")
        for data in self.__flag:
            matches = re.findall(data, request)
            if len(matches) > 0:
                flags.append(matches)
        for data in self.__forbidden:
            matches = re.findall(data, request)
            if len(matches) > 0:
                flags.append(matches)
        print(flags)
        print("*****************")
        reg = re.compile(r'\\')
        matches = re.findall(reg, request)
        print(matches)
        print("#########################")
        return False

    def get_forbidden_list(self):
        return self.__forbidden

    def refresh(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            for i in data['forbidden']:
                self.__forbidden.append(i)
            for i in data['dangerous']:
                self.__flag.append(i)
        data_file.close()

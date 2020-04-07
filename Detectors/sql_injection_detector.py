import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class SqlInjection(Detector):

    __Forbidden_FILE = data_path+"/Detectors/SQLinjection/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.__flag = list()
        self.refresh()

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        request = str(request)
        flags = []
        for data in self.__flag:
            matches = re.findall(data, request)
            print(matches)
            for ma in matches:
                print(ma)
        print("*****************")
        for data in self.__forbidden:
            matches = re.findall(data, request)
            print(matches)
            for ma in matches:
                print(ma)
        print("*****************")
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

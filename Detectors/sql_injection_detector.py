import json
from Detectors import Detector, Sensitivity
from config import data_path


class SqlInjection(Detector):

    __Forbidden_FILE = data_path+"/Detectors/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.refresh()

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        for data in self.__forbidden:
            print(data)

    def get_forbidden_list(self):
        return self.__forbidden

    def refresh(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            self.__forbidden.append(data['forbidden'])
        data_file.close()

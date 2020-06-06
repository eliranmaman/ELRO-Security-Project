import json
from Detectors import Detector, Sensitivity
from config import data_path
import re


class XSSDetector(Detector):
    __Forbidden_FILE = data_path+"/Detectors/XSSDetector/forbidden.json"

    def __init__(self):
        self.__forbidden = list()
        self.__break_characters = list()
        self.refresh()

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        request = str(request).upper()
        request = str(request)

        context_break_list = []
        forbidden_word_list = []
        print("scanning for sql injections")
        # check for context break intentions
        for break_char in self.__break_characters:
            context_breaks = re.findall(break_char, request)
            if len(context_breaks) > 0:
                context_break_list.append(context_breaks)
                if sensitivity == Sensitivity.Sensitive:
                    return True
        # check for forbidden words
        for forbidden_word in self.__forbidden:
            forbidden_words = re.findall(forbidden_word, request)
            if len(forbidden_words) > 0:
                forbidden_word_list.append(forbidden_words)
        # if tries to break context with forbidden words it is probably an attack
        if len(context_break_list) > 0 and len(forbidden_word_list) > 0:
            return True

        return False

    def get_forbidden_list(self):
        return self.__forbidden

    def refresh(self):
        with open(self.__Forbidden_FILE, "r") as data_file:
            data = json.load(data_file)
            for i in data['forbidden']:
                self.__forbidden.append(i)
            for i in data['break_characters']:
                self.__break_characters.append(i)
        data_file.close()

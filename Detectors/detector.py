from Detectors import Sensitivity


class Detector(object):

    def detect(self, request, sensitivity=Sensitivity.Regular, forbidden=None, legitimate=None):
        """
        This method will apply the detector scans on the request and return
        :param legitimate: This will hold a set with a white list expressions e.g: [ " OR 2=2 ", "AND 1=1" ]
        :param forbidden: This will hold a set with extra filters e.g: [ "OR 1=1", "This is an beautiful day" ]
        :param sensitivity: The sensitivity of the detection.
        :param request: the request that the detector need to analyze.
        :return: True in case of unwanted data otherwise False
        """
        raise NotImplementedError()

    def get_forbidden_list(self):
        """
        This method will return a dict with the forbidden list words of the Detector.
        :return: dict
        """
        raise NotImplementedError()

    def refresh(self):
        """
        This function will refresh the detector resources, e.g: the forbidden words.
        :return: None
        """
        raise NotImplementedError()
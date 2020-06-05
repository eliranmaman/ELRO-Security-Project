import enum

# TODO: check if the leggite or the forbidden need to run first in the _pre_processing method. (another reason is the
#       is the fact that forbidden word can be legit.


class Sensitivity(enum.Enum):
    VerySensitive = 0.1
    Sensitive = 0.2
    Regular = 0.3


class Classification(enum.Enum):
    Detected = 1
    Clean = 2
    NoConclusion = 3


class Detector(object):

    def __init__(self):
        self._forbidden = []

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

    def _pre_processing(self, forbidden, legitimate, request):
        """
        This method is to prevent duplicate code (each detector implement this code eventually)
        The method perform check on the legitimate & forbidden lists.
        :param forbidden: the forbidden list
        :param legitimate: the legitimate list
        :param request: the request
        :return: Classification (Enum)
        """
        # Setting the forbidden list
        if forbidden is None:
            forbidden = list()
        forbidden += self.get_forbidden_list()
        # Setting the legitimate list
        if legitimate is None:
            legitimate = list()
        # Checking if the request is in the forbidden list of the server.
        is_legitimate = self._is_legitimate(legitimate, request)
        if is_legitimate == Classification.Clean:
            return Classification.Clean
        is_forbidden = self._is_forbidden(forbidden, request)
        if is_forbidden == Classification.Detected:
            return Classification.Detected
        return Classification.NoConclusion

    def _is_forbidden(self, forbidden, request):
        """
        The above method will perform a case check, if it is found that the request has been identified as belonging
         to the forbidden list, the method will classifies if its Detected or No conclusion.
        :param request: the request
        :return: Classification (Enum)
        """
        raise NotImplementedError()

    def _is_legitimate(self, legitimate, request):
        """
        The above method will perform a case check, if it is found that the request has been identified as belonging
         to the legitimate list, the method will classifies if its Clean or No conclusion
        :param request: the request
        :return: Classification (Enum)
        """
        raise NotImplementedError()

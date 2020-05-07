import enum


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
        # Setting the forbidden list
        if forbidden is None:
            forbidden = list()
        forbidden += self.get_forbidden_list()
        # Setting the legitimate list
        if legitimate is None:
            legitimate = list()
        # Cleaning the request path
        req_path = str(request.path).strip("/")
        # Checking if the path is in the forbidden list of the server.
        for path in forbidden:
            if path in request.path:
                return Classification.Detected
        # Checking if the path is in the legitimate list of the server.
        for path in legitimate:
            if path == req_path:
                return Classification.Clean
        return Classification.NoConclusion

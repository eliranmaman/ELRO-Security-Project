class UPDetector(object):

    def detect(self, parsed_data):
        """
        This method will apply the detector scans on the request and return
        :param parsed_data: Parsed Data (from the parser module) of the response
        :return: True in case of unwanted data otherwise False
        """
        raise NotImplementedError()




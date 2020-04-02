class Proxy(object):

    def __init__(self, port, controller, logger=None):
        """
        :param port: The Proxy Port
        :param controller: The main controller of the ELRO system instance.
        :param logger: The desired logger for the proxy
        """
        raise NotImplementedError()

    def start(self):
        """
        This method will start the proxy on the given port.
        :return: None
        """
        raise NotImplementedError()

    def stop(self):
        """
        This method will close the proxy and realise the resources.
        :return: None
        """
        raise NotImplementedError()
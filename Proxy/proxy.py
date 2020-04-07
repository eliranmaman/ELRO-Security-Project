from config import controller


class Proxy(object):

    _controller = controller

    def __init__(self, port, logger=None):
        """
        :param port: The Proxy Port
        :param controller: The main controller of the ELRO system instance.
        :param logger: The desired logger for the proxy
        """
        self._port = port
        self._running = False
        self._logger = logger

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
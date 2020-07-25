import enum
from Controllers.controller import Controller


class Detectors(enum.Enum):
    SQL_INJ = 1
    XSS_INJ = 2
from enum import Enum
from Controllers.controller import Controller


class Detectors(Enum.enum):
    SQL_INJ = 1,
    XSS_INJ = 2
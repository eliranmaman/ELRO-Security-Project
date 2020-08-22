import enum


class Sensitivity(enum.Enum):
    VerySensitive = 1
    Sensitive = 2
    Regular = 3


class Classification(enum.Enum):
    Detected = 1
    Clean = 2
    NoConclusion = 3


class Detectors(enum.Enum):
    SQL_INJ = 1
    XSS_INJ = 2

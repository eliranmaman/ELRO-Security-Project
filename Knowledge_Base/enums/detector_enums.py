import enum


class Sensitivity(enum.Enum):
    VerySensitive = 0.1
    Sensitive = 0.2
    Regular = 0.3


class Classification(enum.Enum):
    Detected = 1
    Clean = 2
    NoConclusion = 3

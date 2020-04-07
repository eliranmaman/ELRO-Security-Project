from enum import Enum
from Detectors.detector import Detector
from Detectors.sql_injection_detector import SqlInjection as SQLDetector


class Sensitivity(Enum.enum):
    VerySensitive = 0.1
    Sensitive = 0.2
    Regular = 0.3
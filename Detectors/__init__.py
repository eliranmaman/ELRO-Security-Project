from enum import Enum
from Detectors.detector import Detector


class Sensitivity(Enum.enum):
    VerySensitive = 0.1
    Sensitive = 0.2
    Regular = 0.3
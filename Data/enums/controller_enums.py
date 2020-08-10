import enum


class ControllerResponseCode(enum.Enum):
    NotValid = 100
    Valid = 200
    Failed = 404


class RedirectAnswerTo(enum.Enum):
    Client = 0
    Server = 1


class IsAuthorized(enum.Enum):
    Yes = 0
    No = 1
    NoData = 2
    
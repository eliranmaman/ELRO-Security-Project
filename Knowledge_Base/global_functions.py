from datetime import datetime
import traceback

from Knowledge_Base.enums.logs_enums import LogLevel


def create_content_as_str(content):
    my_str = ""
    for item, val in content.__dict__.items():
        my_str += "{}:{} ".format(item, val)
    return my_str.upper()


def to_json(item, ignore_list=None):
    ignore_list = list() if ignore_list is None else ignore_list
    json_data = dict()
    for attr, value in item.__dict__.items():
        if "_sa_instance_state" in attr or attr in ignore_list:
            continue
        json_data[attr] = value

    return json_data


def from_json(json_data, obj):
    for attr, value in json_data.items():
        obj.__dict__[attr] = value
    return obj


def log(msg, level, func, stacktrace=False):
    log_msg = "{} - [{}][{}] {}".format(datetime.now(), level.value, func.__name__, msg)
    log_msg_debug = "{} - [{}][{}] {}".format(datetime.now(), LogLevel.DEBUG, func.__name__, msg)
    print(log_msg)
    if stacktrace:
        traceback.print_exc()
    if level != LogLevel.DEBUG:
        print(log_msg_debug)

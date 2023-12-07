import functools
import logging
import logging.handlers
import os
import struct
import threading
from collections import namedtuple

from twisted.internet import defer
from twisted.protocols.basic import LineReceiver


def pretty(data):
    return data.hex(" ")




def init_logger(logger_name, log_category="", debug=False):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # formatter = logging.Formatter("%(asctime)s %(module)s->%(funcName)s.L%(lineno)s %(message)s")
    formatter = logging.Formatter("%(asctime)s %(module)s->L%(lineno)s %(message)s")
    log_dir = os.path.join(os.path.expanduser("~"), "var", "log", log_category)
    os.makedirs(log_dir, exist_ok=True)
    logfile = os.path.join(log_dir, f"{logger_name.lower()}.log")
    if not logger.handlers:
        rotate_handle = logging.handlers.RotatingFileHandler(
            logfile, maxBytes=1024 * 1024 * 50, backupCount=3, encoding="utf-8"
        )
        rotate_handle.setFormatter(formatter)
        logger.addHandler(rotate_handle)

        if debug:
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)
    return logger

mdb232_logger = init_logger("changer", debug=True)

def log_result(f):

    @defer.inlineCallbacks
    def pretty_log(self, *args, **kwargs):
        clazz = ''
        if self.__class__:
            clazz = self.__class__.__name__
        # mdb232_logger.debug("{}.{} ->".format(clazz, f.__name__))
        try:
            result = yield f(self, *args, **kwargs)
            # str_data = pretty(result)
            # mdb232_logger.debug(f"{clazz}.{f.__name__} <- ")
            defer.returnValue(result)
        except Exception as e:
            mdb232_logger.error("pretty_log error: " + str(e))
            raise e
    return pretty_log



def binary2dict(bin_format, data, names:list):
    Data = namedtuple("Data", names)
    return Data._make(struct.unpack(bin_format, data))._asdict()

def run_in_thread(func):
    @functools.wraps(func)
    def wrapper(*k, **kw):
        t = threading.Thread(target=func, args=k, kwargs=kw)
        t.setDaemon(True)
        t.start()

    return wrapper


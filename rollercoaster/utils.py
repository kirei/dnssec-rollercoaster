import logging
import time
from contextlib import ContextDecorator


class cmtimer(ContextDecorator):
    def __init__(self, msg, logger=None):
        self.msg = msg
        self.logger = logger or logging.getLogger(__name__)

    def __enter__(self):
        self.time = time.perf_counter()
        return self

    def __exit__(self, type, value, traceback):
        elapsed = time.perf_counter() - self.time
        self.logger.debug(f"{self.msg} took {elapsed:.3f} seconds")

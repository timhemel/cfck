import sys
import logging

logger = logging.getLogger(__name__)

class BaseRenderer:
    def __init__(self, render_func):
        self.render_func = render_func
        self.outstream = sys.stdout

    def begin(self):
        pass

    def end(self):
        pass

    def write(self, text, end=''):
        self.outstream.write(text)
        self.outstream.write(end)


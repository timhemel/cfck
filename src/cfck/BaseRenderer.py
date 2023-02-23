import logging

logger = logging.getLogger(__name__)

class BaseRenderer:
    def __init__(self, render_func):
        self.render_func = render_func

    def begin(self):
        pass

    def end(self):
        pass



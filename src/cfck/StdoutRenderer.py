import logging
from .BaseRenderer import BaseRenderer

logger = logging.getLogger(__name__)

class StdoutRenderer(BaseRenderer):

    def feed(self, filename, iterator):
        for finding_vars in iterator:
            s = self.render_func(filename, finding_vars)
            if s is not None:
                print(s)



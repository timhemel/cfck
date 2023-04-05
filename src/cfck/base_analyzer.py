import logging
import yldprolog.engine
from .exception import CfckException

logger = logging.getLogger(__name__)

class BaseAnalyzer:
    def __init__(self, ctx):
        self.query_engine = yldprolog.engine.YP()
        self.set_prolog_base_functions()
        self.choose_renderer(ctx)
        # TODO: rules

    def set_prolog_base_functions(self):
        pass

    def add_rules(self, compiled_rules):
        self.query_engine.load_script_from_string(compiled_rules, overwrite=False)



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

    def run(self, inputs):
        self.inputs = inputs

        # TODO: processes one input at a time, make this more flexible
        self.renderer.begin()

        for inp_fn in inputs:
            logger.debug(f'Processing {inp_fn}')
            try:
                self.parse_input(inp_fn)
                r = self.ask('q')

                logger.debug(f'rendering results...')
                self.renderer.feed(inp_fn, r)
                logger.debug(f'rendered results.')
            except CfckException as e:
                logger.error(f'Could not parse file {inp_fn}: {e}')

        self.renderer.end()



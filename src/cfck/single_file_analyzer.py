import logging

logger = logging.getLogger(__name__)

class SingleFileAnalyzer:
    '''A mixin that analyzes one individual file at a time.'''

    def run(self, inputs):
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



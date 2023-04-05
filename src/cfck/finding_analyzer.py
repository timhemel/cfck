import logging
from .StdoutRenderer import StdoutRenderer, structured_quickfix_finding, render_plain
from .SarifRenderer import SarifRenderer, sarif_log_updater, sarif_result_updater, structured_sarif_finding

logger = logging.getLogger(__name__)

_renderers = {
    'vim': StdoutRenderer(structured_quickfix_finding),
    'sarif': SarifRenderer(structured_sarif_finding),
    'plain': StdoutRenderer(render_plain)
}

def choose_finding_renderer(outformat):
    renderer = _renderers.get(outformat)
    if renderer is not None:
        return renderer

class FindingAnalyzer:
    '''A mixin that selects renderers for findings.'''

    def __init__(self, ctx):
        logger.debug('FindingAnalyzer.__init__()')
        pass

    def choose_renderer(self, ctx):
        logger.debug(f'findiganakyzererfchoosrerender {dir(ctx)}')

        outformat = ctx.params['outformat']
        self.renderer = choose_finding_renderer(outformat)
        if self.renderer is None:
            raise CfckException('Renderer {outformat} is not supported by this analyzer.')


#!/usr/bin/env python3

import click
import sys
import io
import pathlib
import logging
from yldprolog.compiler import compile_prolog_from_file
from .StdoutRenderer import StdoutRenderer
from .SarifRenderer import SarifRenderer, sarif_finding
from .exception import CfckException

from .XMLAnalyzer import XMLAnalyzer
from .SarifAnalyzer import SarifAnalyzer

logger = logging.getLogger(__name__)


def quickfix_finding(filename, query_vars):
    '''[ruleid, level, message_format, locations, *finding_vars]'''
    rule_id = query_vars[0]
    level = query_vars[1]
    message = query_vars[2].format(*query_vars[4:])
    locations = [ f'{path}:{startloc[0]}:{startloc[1]}' for path, startloc, endloc in query_vars[3] ]
    if locations == []:
        return None  # No use reporting quickfix without location
    return f'{locations[0]}:{level}:{rule_id}:{message}'

def render_plain(filename, finding_vars):
    # line = finding_vars[1].sourceline
    logger.debug(f'render_plain: {filename=}, {finding_vars=}')
    message = finding_vars[0].format(*finding_vars[1:])
    return message


analyzers = {
        'xml': XMLAnalyzer,
        'sarif': SarifAnalyzer
    }

@click.command()
@click.pass_context
@click.option('-a','--analyzer')
@click.option('-r','--rules', type=click.Path(path_type=pathlib.Path))
@click.option('-d','--debug', type=bool, is_flag=True, default=False)
@click.option('--vim', 'outformat', is_flag=True, flag_value='vim', default=True)
@click.option('--sarif', 'outformat', is_flag=True, flag_value='sarif')
@click.option('--plain', 'outformat', is_flag=True, flag_value='plain')
@click.option('--secure/--insecure', default=True, help="validate or don't validate XML with defusedxml")
@click.argument('inp', nargs=-1, type=click.Path(path_type=pathlib.Path))
def analyze(ctx, analyzer, rules, debug, outformat, secure, inp):

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    compiled_rules = compile_prolog_from_file(rules)
    logger.debug(f'compiled rules from file {rules}')

    try:
        analysis = analyzers[analyzer](ctx)
        logger.debug(f'Using analyzer {analyzer}')
    except KeyError as e:
        raise click.ClickException(f'Could not find analyzer: {analyzer}')

    #x = XMLAnalyzer()
    #x.add_rules(compiled_rules)
    analysis.add_rules(compiled_rules)

    renderers = {
            'vim': StdoutRenderer(quickfix_finding),
            'sarif': SarifRenderer(sarif_finding),
            'plain': StdoutRenderer(render_plain)
    }
    renderer = renderers[outformat]

    renderer.begin()

    for inp_fn in inp:
        logger.debug(f'Processing {inp_fn}')
        try:
            analysis.parse_input(inp_fn)
            r = analysis.ask('q')

            logger.debug(f'rendering results...')
            renderer.feed(inp_fn, r)
            logger.debug(f'rendered results.')
        except CfckException as e:
            logger.error(f'Could not parse file {inp_fn}: {e}')

    renderer.end()

if __name__=="__main__":
    analyze()


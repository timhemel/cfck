#!/usr/bin/env python3

import click
import sys
import io
import pathlib
import logging
from yldprolog.compiler import compile_prolog_from_file
from .StdoutRenderer import StdoutRenderer
from .SarifRenderer import SarifRenderer, sarif_finding, structured_sarif_finding
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

def sarif_importance(kind, level):
    if level in ['error','warning','note']:
        return level
    if kind in ['informational','notApplicable','pass']:
        return 'note'
    if kind in ['open','review']:
        return 'warning'
    return 'warning'

def structured_quickfix_finding(filename, query_vars):
    '''query_vars is a list that contains functors'''
    qv_dict = dict(query_vars)
    logger.debug(f'structured_quickfix_finding: {filename}, {qv_dict}')
    rule_id = qv_dict.get('ruleid',['missing_rule'])[0]
    level = qv_dict.get('level',[''])[0]
    kind = qv_dict.get('kind',[''])[0]
    importance = sarif_importance(kind, level)

    message = qv_dict.get('message',('',[])) # format(*query_vars[4:])
    message_string = message[0].format(*message[1])
    logger.debug(f'structured_quickfix_finding: locs = {qv_dict.get("locations")}')
    locs = qv_dict.get('locations', [[]])[0]
    locations = [ f'{path}:{startloc[0]}:{startloc[1]}' for path, startloc, endloc in locs ]
    if locations == []:
        return None  # No use reporting quickfix without location
    return f'{locations[0]}:{importance}:{rule_id}:{message_string}'

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
            'vim': StdoutRenderer(structured_quickfix_finding),
            'sarif': SarifRenderer(structured_sarif_finding),
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


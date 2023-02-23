#!/usr/bin/env python3

from lxml import etree
from defusedxml import ElementTree as defused_etree
from defusedxml.common import DefusedXmlException
import click
import sys
import io
import logging
from yldprolog.compiler import compile_prolog_from_file
from .StdoutRenderer import StdoutRenderer
from .SarifRenderer import SarifRenderer, sarif_finding

from .XMLAnalyzer import XMLAnalyzer

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

def parse_xml(inp_fn, secure):
    '''this function will parse the XML. If secure is True, use the defusedxml library to validate the input before letting
    lxml parse it.'''
    with open(inp_fn,'r') as inp_f:
        if secure:
            t = defused_etree.parse(inp_fn)
        t = etree.parse(inp_fn)
        return t

@click.command()
@click.option('-r','--rules', type=click.Path())
@click.option('-d','--debug', type=bool, is_flag=True, default=False)
@click.option('--vim', 'outformat', is_flag=True, flag_value='vim', default=True)
@click.option('--sarif', 'outformat', is_flag=True, flag_value='sarif')
@click.option('--plain', 'outformat', is_flag=True, flag_value='plain')
@click.option('--secure/--insecure', default=True, help="validate or don't validate XML with defusedxml")
@click.argument('inp', nargs=-1, type=click.Path())
def analyze(rules, debug, outformat, secure, inp):
    compiled_rules = compile_prolog_from_file(rules)

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    x = XMLAnalyzer()
    x.add_rules(compiled_rules)
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
            t = parse_xml(inp_fn, secure)
            x.set_xml(t)
            x.set_path(inp_fn)

            r = x.ask('q')

            logger.debug(f'rendering results...')
            renderer.feed(inp_fn, r)
            logger.debug(f'rendered results.')
        except DefusedXmlException as e:
            logger.error(f'File {inp_fn} contains insecure XML: {e}')

    renderer.end()

if __name__=="__main__":
    analyze()


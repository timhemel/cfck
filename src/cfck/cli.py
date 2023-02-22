#!/usr/bin/env python3

from lxml import etree
from defusedxml import ElementTree as defused_etree
from defusedxml.common import DefusedXmlException
import click
import sys
import io
import logging
from yldprolog.compiler import compile_prolog_from_file
from sarif_om._location import Location
from sarif_om._physical_location import PhysicalLocation

from .XMLAnalyzer import XMLAnalyzer

logger = logging.getLogger(__name__)

def render_finding(filename, finding_vars):
    line = finding_vars[1].sourceline
    message = finding_vars[0].format(*finding_vars[1:])
    return f'{filename}:{line}:0:{message}'

def sarif_finding(filename, finding_vars):
    return 'TODO: sarif_finding'
    line = finding_vars[1].sourceline
    #location = Location(
    message = finding_vars[0].format(*finding_vars[1:])

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
    for inp_fn in inp:
        logger.debug(f'Processing {inp_fn}')
        try:
            t = parse_xml(inp_fn, secure)
            x.set_xml(t)

            r = x.ask('q')

            renderers = {
                    'vim': render_finding,
                    'sarif': sarif_finding,
                    'plain': render_plain
            }

            render_fun = renderers[outformat]

            logger.debug(f'rendering results...')
            for y in r:
                print(render_fun(inp_fn, y))
            logger.debug(f'rendered results.')
        except DefusedXmlException as e:
            logger.error(f'File {inp_fn} contains insecure XML: {e}')

if __name__=="__main__":
    analyze()


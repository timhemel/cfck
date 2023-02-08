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

def render_finding(filename, finding_vars):
    line = finding_vars[1].sourceline
    message = finding_vars[0].format(*finding_vars[1:])
    return f'{filename}:{line}:0:{message}'

def sarif_finding(filename, finding_vars):
    line = finding_vars[1].sourceline
    #location = Location(
    message = finding_vars[0].format(*finding_vars[1:])


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
@click.option('--secure/--insecure', default=True, help="validate or don't validate XML with defusedxml")
@click.argument('inp', nargs=-1, type=click.Path())
def analyze(rules, debug, outformat, secure, inp):
    compiled_rules = compile_prolog_from_file(rules)

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    x = XMLAnalyzer()
    x.add_rules(compiled_rules)
    for inp_fn in inp:
        logging.debug(f'Processing {inp_fn}')
        try:
            t = parse_xml(inp_fn, secure)
            x.set_xml(t)

            r = x.ask('q')

            if outformat == 'vim':
                for y in r:
                    print(render_finding(inp_fn, y))
            elif outformat == 'sarif':
                print(f'TODO: {outformat}')
                for y in r:
                    result = sarif_finding(inp_fn, y)
                    print(result)
        except DefusedXmlException as e:
            logging.error(f'File {inp_fn} contains insecure XML: {e}')

if __name__=="__main__":
    analyze()


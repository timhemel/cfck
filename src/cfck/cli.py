#!/usr/bin/env python3

from lxml import etree
from defusedxml import ElementTree as defused_etree
from defusedxml.common import DefusedXmlException
import click
import sys
import io
import logging
from yldprolog.compiler import compile_prolog_from_file

from .XMLAnalyzer import XMLAnalyzer

def render_finding(filename, finding_vars):
    line = finding_vars[1].sourceline
    message = finding_vars[0].format(*finding_vars[1:])
    return f'{filename}:{line}:0:{message}'

def secure_parse(inp_fn):
    '''this function will parse the XML with the defusedxml library to validate/sanitize the input for lxml'''
    t = defused_etree.parse(inp_fn)
    out_f = io.StringIO()
    t.write(out_f, encoding='unicode')
    s = out_f.getvalue()
    t = etree.fromstring(s)
    return t


@click.command()
@click.option('-r','--rules', type=click.Path())
@click.option('-d','--debug', type=bool, is_flag=True, default=False)
@click.argument('inp', nargs=-1, type=click.Path())
def analyze(rules, debug, inp):
    compiled_rules = compile_prolog_from_file(rules)

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    x = XMLAnalyzer()
    x.add_rules(compiled_rules)
    for inp_fn in inp:
        logging.debug(f'Processing {inp_fn}')
        try:
            t = secure_parse(inp_fn)
            x.set_xml(t)

            r = x.ask('q')

            for y in r:
                print(render_finding(inp_fn, y))
        except DefusedXmlException as e:
            raise click.ClickException(f'Insecure XML: {e}')

if __name__=="__main__":
    analyze()


#!/usr/bin/env python3

#
# fsce: find security configuration errors
#
#

#from lxml import etree
from defusedxml import ElementTree as etree
import click
from yldprolog.compiler import compile_prolog_from_file

from XMLAnalyzer import XMLAnalyzer

def render_finding(f, finding_vars):
    line = finding_vars[1].sourceline
    filename = f.name
    message = finding_vars[0].format(*finding_vars[1:])
    return f'{filename}:{line}:0:{message}'

@click.command()
@click.option('-r','--rules', type=click.Path())
@click.option('-d','--debug', type=bool, is_flag=True, default=False)
@click.argument('inp', nargs=-1, type=click.File('r'))
def analyze(rules, debug, inp):
    # print(f'{t=}')
    # print(f'tree={t.getroot()}')

    compiled_rules = compile_prolog_from_file(rules)

    x = XMLAnalyzer()
    for inp_file in inp:
        # print(f'Processing {inp_file.name}')
        t = etree.parse(inp_file)
        x.set_xml(t)
        x.set_debug(debug)

        x.add_rules(compiled_rules)

        r = x.ask('q')

        for y in r:
            print(render_finding(inp_file, y))
            # print(dir(y[1]))
            # print(y[1].sourceline)
            # print(y[0].format(*y[1:]))


if __name__=="__main__":
    analyze()


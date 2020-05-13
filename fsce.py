#!/usr/bin/env python3

#
# fsce: find security configuration errors
#
#

from lxml import etree
import click
from yldprolog.compiler import compile_prolog_from_file

from XMLAnalyzer import XMLAnalyzer

@click.command()
@click.option('-r','--rules', type=click.Path())
@click.argument('inp', type=click.File('r'), default='-')
def analyze(rules, inp):
    t = etree.parse(inp)

    compiled_rules = compile_prolog_from_file(rules)

    x = XMLAnalyzer()
    x.set_xml(t)

    x.add_rules(compiled_rules)

    r = x.ask('q')

    for y in r:
        print(y[0] % y[1:])


if __name__=="__main__":
    analyze()


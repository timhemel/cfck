#!/usr/bin/env python3

import click
import sys
import os
import io
import pathlib
import logging
import importlib
import importlib.resources
from yldprolog.compiler import compile_prolog_from_file
from .exception import CfckException

logger = logging.getLogger(__name__)


def quickfix_finding(filename, query_vars):
    '''[ruleid, level, message_format, locations, *finding_vars]'''
    rule_id = query_vars[0]
    level = query_vars[1]
    try:
        message = query_vars[2].format(*query_vars[4:])
    except KeyError:
        message = query_vars[2]
    locations = [ f'{path}:{startloc[0]}:{startloc[1]}' for path, startloc, endloc in query_vars[3] ]
    if locations == []:
        return None  # No use reporting quickfix without location
    return f'{locations[0]}:{level}:{rule_id}:{message}'

def load_analyzer_module_from_path(module_path):
    spec=importlib.util.spec_from_file_location('analyzer',module_path)
    analyzer_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer_module)
    return analyzer_module

def check_module_path(path):
    if path.suffix != '.py':
        path = path.with_suffix('.py')
    if path.exists():
        return path
    return None

def get_analyzer_module(analyzer):
    # get analyzer from a file
    logger.debug(f'get_analyzer_module: searching for analyzer {analyzer}')
    module_path = check_module_path(pathlib.Path(analyzer))
    if module_path is not None:
        logger.debug(f'get_analyzer_module: found path {module_path}')
        return load_analyzer_module_from_path(module_path)
    # get it from the configured path
    cfck_module_path = os.environ.get('CFCK_ANALYZERS_PATH')
    if cfck_module_path is not None:
        for search_dir in cfck_module_path.split(':'):
            logger.debug(f'get_analyzer_module: searching path {search_dir}')
            module_path = check_module_path(pathlib.Path(search_dir) / analyzer)
            if module_path is not None:
                logger.debug(f'get_analyzer_module: found path {module_path}')
                return load_analyzer_module_from_path(module_path)
    # get it from the built-in path
    try:
        module = importlib.import_module(f'cfck.analysis.{analyzer}')
        logger.debug(f'get_analyzer_module: found module cfck.analysis.{analyzer}')
        return module
    except ModuleNotFoundError as e:
        logger.debug(f'get_analyzer_module: could not load module cfck.analysis.{analyzer}: {e}')
        pass
    return None


@click.command()
@click.pass_context
@click.option('-a','--analyzer')
@click.option('-r','--rules', type=click.Path(path_type=pathlib.Path))
@click.option('-d','--debug', type=bool, is_flag=True, default=False)
@click.option('-f', '--outformat', default='vim')
@click.option('-O', '--option', multiple=True)
@click.option('-o','--outfile', type=click.Path(path_type=pathlib.Path))
#@click.option('--vim', 'outformat', is_flag=True, flag_value='vim', default=True)
#@click.option('--sarif', 'outformat', is_flag=True, flag_value='sarif')
#@click.option('--plain', 'outformat', is_flag=True, flag_value='plain')
#@click.option('--secure/--insecure', default=True, help="validate or don't validate XML with defusedxml")
@click.argument('inputs', nargs=-1, type=click.Path(path_type=pathlib.Path))
def analyze(ctx, analyzer, rules, debug, outformat, option, outfile, inputs):

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    compiled_rules = compile_prolog_from_file(rules)
    logger.debug(f'compiled rules from file {rules}')

    analyzer_module = get_analyzer_module(analyzer)

    if analyzer_module is None:
        raise click.ClickException(f'Could not find analyzer: {analyzer}')

    analysis = analyzer_module.create_analyzer(ctx)

    logger.debug(f'Using analyzer {analyzer}')

    #x = XMLAnalyzer()
    #x.add_rules(compiled_rules)
    analysis.add_rules(compiled_rules)

    #analysis.renderer = renderer
    analysis.run(inputs)
    return
    #--------

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


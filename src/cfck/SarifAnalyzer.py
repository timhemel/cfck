import json
import sarif
from sarif.sarif_file import SarifFile
import logging
import yldprolog.engine
from yldprolog.engine import get_value, to_python, unify
from .exception import CfckException


logger = logging.getLogger(__name__)

class SarifAnalyzer:

    def __init__(self, ctx):
        self.query_engine = yldprolog.engine.YP()
        self.set_prolog_base_functions()
        self.sarif_file = None
        self.path = None

    def set_prolog_base_functions(self):
        self.query_engine.register_function('sarif_result', self.sarif_result)
        self.query_engine.register_function('sarif_locations', self.sarif_locations)
        self.query_engine.register_function('sarif_message', self.sarif_message)
        self.query_engine.register_function('sarif_level', self.sarif_level)

    def add_rules(self, compiled_rules):
        self.query_engine.load_script_from_string(compiled_rules, overwrite=False)

    def parse_input(self, path):
        # TODO: sariffile set via *paths
        #help(sarif.sarif_file.SarifFile)
        with path.open('r') as infile:
            data = json.load(infile)
        self.sarif_file = SarifFile(path, data)
        # print(self.sarif_file.get_file_name())
        #print(self.sarif_file.get_records())
        self.results = self.sarif_file.get_results()
        #print(self.results)
        #print(self.sarif_file.get_distinct_tool_names())

    def ask(self, query):
        v = self.query_engine.variable()
        q = self.query_engine.query(query, [v])
        return [ to_python(v) for r in q ]

    def set_sarif_file(self, sarif_file):
        self.sarif_file = sarif_file
        logger.debug(f'set_sarif_file: {sarif_file =}')

    def set_path(self, path):
        self.path = path

    def sarif_locations_to_prolog(self, locations):
        def location_to_prolog(location):
            logger.debug(f'{location=}')
            uri = location['physicalLocation']['artifactLocation']['uri']
            region = location['physicalLocation']['region']
            loc = self.query_engine.makelist([ self.query_engine.atom(uri),
                self.query_engine.makelist([
                    self.query_engine.atom(region['startLine']),
                    self.query_engine.atom(region.get('startColumn',0))
                ]),
                self.query_engine.makelist([
                    self.query_engine.atom(region['endLine']),
                    self.query_engine.atom(region.get('endColumn',0))
                ])])
            return loc
        locs = self.query_engine.makelist([location_to_prolog(l) for l in locations])
        return locs


    def sarif_result(self, result_index, rule):
        logger.debug(f'sarif_result')
        for index, result in enumerate(self.results):
            logger.debug(f'sarif_result: {index},{result=}')
            for y in unify(result_index, self.query_engine.atom(index)):
                rule_id = result['ruleId']
                logger.debug(f'sarif_result: {rule_id=}')
                for x in unify(rule, self.query_engine.atom(rule_id)):
                    logger.debug(f'sarif_result: match {rule_id=}')
                    yield False

    def sarif_locations(self, result_index, locations):
        logger.debug(f'sarif_locations')
        for index, result in enumerate(self.results):
            logger.debug(f'sarif_locations: {index},{result=}')
            for y in unify(result_index, self.query_engine.atom(index)):
                locs = self.sarif_locations_to_prolog(result['locations'])
                logger.debug(f'sarif_locations: {locs=} {locations=} {self.query_engine.atom(locations)=}')
                for x in unify(locations, locs):
                    yield False

    def sarif_message(self, result_index, message):
        logger.debug(f'sarif_message')
        for index, result in enumerate(self.results):
            logger.debug(f'sarif_message: {index},{result=}')
            for y in unify(result_index, self.query_engine.atom(index)):
                # TODO:decide how to handle formatting
                msg = result['message']['text']
                for x in unify(message, self.query_engine.atom(msg)):
                    yield False

    def sarif_level(self, result_index, level):
        logger.debug(f'sarif_level')
        for index, result in enumerate(self.results):
            logger.debug(f'sarif_level: {index},{result=}')
            for y in unify(result_index, self.query_engine.atom(index)):
                lvl = result.get('level', 'warning')
                for x in unify(level, self.query_engine.atom(lvl)):
                    yield False

    def lowercase(self, val1, val2):
        logger.debug(f'lowercase: {val1}={val2}')
        # val1 must be instantiated
        v = self.query_engine.atom(to_python(val1).lower())
        for x in unify(val2, v):
            yield False

    def version_at_least(self, version1, version2):
        # version1 and version2 must be instantiated
        v1 = to_python(version1).split('.')
        v2 = to_python(version2).split('.')
        if v2 >= v1:
            yield False

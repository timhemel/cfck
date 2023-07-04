import re
import lxml
from lxml import etree
from defusedxml import ElementTree as defused_etree
from defusedxml.common import DefusedXmlException
import logging
import yldprolog.engine
from yldprolog.engine import get_value, to_python, unify
from cfck.exception import CfckException
from cfck.base_analyzer import BaseAnalyzer
from cfck.finding_analyzer import FindingAnalyzer
from cfck.single_file_analyzer import SingleFileAnalyzer

logger = logging.getLogger(__name__)

def parse_xml(inp_fn, secure):
    '''this function will parse the XML. If secure is True, use the defusedxml library to validate the input before letting
    lxml parse it.'''
    if secure:
        t = defused_etree.parse(str(inp_fn))
    t = etree.parse(str(inp_fn))
    return t

class XMLAnalyzer(BaseAnalyzer, FindingAnalyzer, SingleFileAnalyzer):

    # See https://lxml.de/xpathxslt.html
    namespaces = { "re": "http://exslt.org/regular-expressions" }

    def __init__(self, ctx):
        super().__init__(ctx)
        self.xml_tree = None
        self.insecure = False
        if ctx.params['option']:
            self.insecure = ctx.params['option'][0] == 'insecure'
        self.path = None

    def choose_renderer(self, ctx):
        super().choose_renderer(ctx)

    def set_prolog_base_functions(self):
        super().set_prolog_base_functions()
        self.query_engine.register_function('xpath', self.get_xpath_value)
        self.query_engine.register_function('fullxpath', self.get_full_xpath_value)
        self.query_engine.register_function('relxpath', self.get_relxpath_value)
        self.query_engine.register_function('tag', self.tag)
        self.query_engine.register_function('attr', self.attr)
        self.query_engine.register_function('text', self.text)
        self.query_engine.register_function('optional_attr', self.optional_attr)
        self.query_engine.register_function('nodelocation', self.node_location)
        self.query_engine.register_function('lowercase', self.lowercase)
        self.query_engine.register_function('integer_add', self.integer_add)
        self.query_engine.register_function('version_at_least', self.version_at_least)
        self.query_engine.register_function('stringmatch', self.string_match)
        self.query_engine.register_function('istringmatch', self.istring_match)
        self.query_engine.register_function('string_replace', self.string_replace)

    def parse_input(self, path):
        try:
            t = parse_xml(path, not self.insecure)
            self.set_xml(t)
            self.path = str(path)
        except DefusedXmlException as e:
            raise CfckException(f'Insecure XML ({e})')

    def ask(self, query):
        v = self.query_engine.variable()
        q = self.query_engine.query(query, [v])
        return [ to_python(v) for r in q ]

    def set_xml(self, xml_tree):
        self.xml_tree = xml_tree
        logger.debug(f'set_xml: {xml_tree =}')
        logger.debug(f'set_xml: {xml_tree.getroot() =}')

    def get_xpath_value(self, query, variable):
        logger.debug(f'query: {to_python(query)}')
        r = self.xml_tree.iterfind(to_python(query))
        for y in r:
                logger.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        
    def get_full_xpath_value(self, query, variable):
        try:
            logger.debug(f'query: {to_python(query)}')
            r = self.xml_tree.xpath(to_python(query), namespaces=self.namespaces)
            for y in r:
                logger.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            logger.error(f'xpath exception {e} on query {to_python(query)}')

    def get_relxpath_value(self, element, query, variable):
        elt = to_python(element)
        try:
            logger.debug(f'query: {to_python(query)}')
            logger.debug(f'elt: {elt}')
            # r = elt.xpath(to_python(query))
            r = elt.iterfind(to_python(query))
            for y in r:
                logger.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            logger.error(f'relxpath: {e} {to_python(query)}')

    def tag(self, element, tagname):
        elt = to_python(element)
        logger.debug(f'elt: {elt!r}, {tagname!r} {elt.tag=} {dir(elt)}')
        for y in unify(tagname, self.query_engine.atom(elt.tag)):
            yield False


    def attr(self, element, key, value):
        elt = to_python(element)
        logger.debug(f'elt: {elt!r}, {key!r}, {value!r}')
        logger.debug(elt.items())
        for k,v in elt.items():
            for x in unify(key, self.query_engine.atom(k)):
                for y in unify(value, self.query_engine.atom(v)):
                        logger.debug(f'attr: {k}={v}')
                        yield False

    def optional_attr(self, element, key, value, default):
        # key and default need to be instantiated
        elt = to_python(element)
        logger.debug(f'element: {elt!r}')
        v = elt.get(to_python(key), to_python(default))
        for y in unify(value, self.query_engine.atom(v)):
            logger.debug(f'optional_attr: {to_python(key)}={v}')
            yield False

    def text(self, element, value):
        elt = to_python(element)
        logger.debug(f'element: {elt!r}')
        for x in unify(value, self.query_engine.atom(elt.text)):
            yield False

    def node_location(self, node, v):
        elt = to_python(node)
        logger.debug(f'node_location: {node=}')
        loc = self.query_engine.atom( (self.path, (elt.sourceline,0), (elt.sourceline,0)) )
        for x in unify(v, loc):
            yield False

    def lowercase(self, val1, val2):
        logger.debug(f'lowercase: {val1}={val2}')
        # val1 must be instantiated
        v = self.query_engine.atom(to_python(val1).lower())
        for x in unify(val2, v):
            yield False

    def integer_add(self, num1, num2, num3):
        # num1 and num2 must be instantiated
        num1_v = int(to_python(num1))
        num2_v = int(to_python(num2))
        sum = self.query_engine.atom(to_python(num1_v + num2_v))
        for x in unify(num3, sum):
            yield False

    def version_at_least(self, version1, version2):
        # version1 and version2 must be instantiated
        v1 = to_python(version1).split('.')
        v2 = to_python(version2).split('.')
        if v2 >= v1:
            yield False

    def string_match(self, text, pattern):
        # assume that text and pattern are instantiated
        text_value = to_python(text)
        pattern_value = to_python(pattern)
        if re.search(pattern_value, text_value):
            yield False

    def istring_match(self, text, pattern):
        # assume that text and pattern are instantiated
        text_value = to_python(text)
        pattern_value = to_python(pattern)
        if re.search(pattern_value, text_value, re.IGNORECASE):
            yield False

    def string_replace(self, source, pattern, replacement, destination):
        '''destination is source with pattern replaced with replacement'''
        # assume that source and pattern and replacement are instantiated
        source_v = str(to_python(source))
        pattern_v = str(to_python(pattern))
        replacement_v = str(to_python(replacement))
        dest_v = source_v.replace(pattern_v, replacement_v)
        dest_a = self.query_engine.atom(dest_v)
        for x in unify(destination, dest_a):
            yield False

def create_analyzer(ctx):
    return XMLAnalyzer(ctx)

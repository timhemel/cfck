import lxml
import logging
import yldprolog.engine
from yldprolog.engine import get_value, to_python, unify



class XMLAnalyzer:

    # TODO: check if we need this
    namespaces = { "re": "http://exslt.org/regular-expressions" }

    def __init__(self):
        self.query_engine = yldprolog.engine.YP()
        self.set_prolog_base_functions()
        self.xml_tree = None

    def set_prolog_base_functions(self):
        self.query_engine.register_function('xpath', self.get_xpath_value)
        self.query_engine.register_function('relxpath', self.get_relxpath_value)
        self.query_engine.register_function('attr', self.attr)
        self.query_engine.register_function('text', self.text)
        self.query_engine.register_function('optional_attr', self.optional_attr)
        self.query_engine.register_function('lowercase', self.lowercase)
        self.query_engine.register_function('version_at_least', self.version_at_least)

    def add_rules(self, compiled_rules):
        self.query_engine.load_script_from_string(compiled_rules, overwrite=False)


    def ask(self, query):
        v = self.query_engine.variable()
        q = self.query_engine.query(query, [v])
        return [ to_python(v) for r in q ]

    def set_xml(self, xml_tree):
        self.xml_tree = xml_tree

    def get_xpath_value(self, query, variable):
        logging.debug(f'query: {to_python(query)}')
        r = self.xml_tree.iterfind(to_python(query))
        for y in r:
                logging.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        
    def xget_xpath_value(self, query, variable):
        try:
            logging.debug(f'query: {to_python(query)}')
            r = self.xml_tree.xpath(to_python(query), namespaces=self.namespaces)
            for y in r:
                logging.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            print("ERROR (xpath):", e, to_python(query))

    def get_relxpath_value(self, element, query, variable):
        elt = to_python(element)
        try:
            logging.debug(f'query: {to_python(query)}')
            logging.debug(f'elt: {elt}')
            r = elt.xpath(to_python(query))
            for y in r:
                logging.debug(f'{to_python(query)} = {y!r}')
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            logging.error(f'relxpath: {e} {to_python(query)}')


    def attr(self, element, key, value):
        elt = to_python(element)
        logging.debug(f'elt: {elt!r}')
        for k,v in elt.items():
            for x in unify(key, self.query_engine.atom(k)):
                for y in unify(value, self.query_engine.atom(v)):
                        logging.debug(f'attr: {k}={v}')
                        yield False

    def optional_attr(self, element, key, value, default):
        # key and default need to be instantiated
        elt = to_python(element)
        logging.debug(f'element: {elt!r}')
        v = elt.get(to_python(key), to_python(default))
        for y in unify(value, self.query_engine.atom(v)):
            logging.debug(f'optional_attr: {to_python(key)={v}')
            yield False

    def text(self, element, value):
        elt = to_python(element)
        logging.debug(f'element: {elt!r}')
        for x in unify(value, self.query_engine.atom(elt.text)):
            yield False

    def lowercase(self, val1, val2):
        logging.debug(f'lowercase: {val1}={val2}')
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



import lxml
import yldprolog.engine
from yldprolog.engine import get_value, to_python, unify



class XMLAnalyzer:

    def __init__(self):
        self.query_engine = yldprolog.engine.YP()
        self.set_prolog_base_functions()
        self.xml_tree = None

    def set_prolog_base_functions(self):
        self.query_engine.register_function('xpath', self.get_xpath_value)
        self.query_engine.register_function('attr', self.attr)
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

    def set_debug(self, debug):
        self.debug = debug
        
    def get_xpath_value(self, query, variable):
        try:
            self._debug("DEBUG: query: %s" % (to_python(query)))
            r = self.xml_tree.xpath(to_python(query))
            for y in r:
                self._debug("DEBUG: %s = %s" % (to_python(query), repr(y)))
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            print("ERROR (xpath):", e, to_python(query))

    def attr(self, element, key, value):
        elt = to_python(element)
        self._debug("element", repr(elt))
        for k,v in elt.items():
            for x in unify(key, self.query_engine.atom(k)):
                for y in unify(value, self.query_engine.atom(v)):
                        self._debug("DEBUG: attr: %s=%s" % (k,v))
                        yield False

    def lowercase(self, val1, val2):
        self._debug("DEBUG: lowercase: %s=%s" % (val1,val2))
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

    def _debug(self, *msg):
        if self.debug:
            print(" ".join(msg))


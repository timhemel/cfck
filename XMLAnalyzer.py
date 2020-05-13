
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
            r = self.xml_tree.xpath(to_python(query))
            for y in r:
                self._debug("element", repr(y))
                for _ in unify(variable, self.query_engine.atom(y)):
                    yield False
        except lxml.etree.XPathEvalError as e:
            print("ERROR:", e)

    def _debug(self, *msg):
        if self.debug:
            print(" ".join(msg))


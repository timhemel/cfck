import logging

import json
import bisect
from attrs import asdict
from attrs import has, fields
import cattrs
from cattrs.gen import make_dict_unstructure_fn, override
from sarif_om import SarifLog, Run, Tool, ToolComponent, Result, PhysicalLocation, ArtifactLocation, Region, ReportingDescriptor, Message

from .BaseRenderer import BaseRenderer

logger = logging.getLogger(__name__)

def rename_schema_field(a):
    try:
        return a.metadata['schema_property_name']
    except KeyError:
        return a.name

def to_schema_fields_unstructure(cls):
    return make_dict_unstructure_fn(cls, converter, **{
        a.name: override(rename=rename_schema_field(a)) for a in fields(cls)
    })

converter = cattrs.Converter()
converter.register_unstructure_hook_factory(has, to_schema_fields_unstructure)

def clear_none_values(obj):
    if isinstance(obj,dict):
        return dict((k,clear_none_values(v)) for k,v in obj.items() if v is not None)
    elif isinstance(obj,list):
        return list(clear_none_values(v) for v in obj)
    elif isinstance(obj,tuple):
        return tuple(clear_none_values(v) for v in obj)
    else:
        return obj

class SarifRenderer(BaseRenderer):

    def __init__(self, render_func):
        super().__init__(render_func)
        self.sarif_log = None

    def begin(self):
        run = Run(tool=Tool(driver=ToolComponent(name='cfck',version='0.0.1')), results=[])
        self.sarif_log = SarifLog(runs=[run],version='2.1.0')

    def feed(self, filename, iterator):
        self.sarif_log.runs[0].results += [ self.render_func(filename, finding_vars) for finding_vars in iterator ]

    def add_rules(self):
        for run in self.sarif_log.runs:
            rule_ids = sorted([result.rule_id for result in run.results ])
            run.tool.driver.rules = [ ReportingDescriptor(id=rid, name=rid) for rid in rule_ids ]
            for result in run.results:
                rule_index = bisect.bisect_left(rule_ids, result.rule_id)
                result.rule_index = rule_index

    def end(self):
        self.add_rules()
        renamed_log = clear_none_values(converter.unstructure(self.sarif_log))
        print(json.dumps(renamed_log))


def sarif_location(path, startloc, endloc):
    logger.debug(f'sarif_location: {path=}, {startloc=}, {endloc=}')
    region = Region(start_line=startloc[0], start_column=startloc[1], end_line=endloc[0], end_column=endloc[1], byte_offset=None, char_offset=None)
    artifact_location = ArtifactLocation(uri=path, index=None)
    loc = { 'physicalLocation': PhysicalLocation(artifact_location=artifact_location, region=region) }
    logger.debug(f'sarif_location: {loc=}')
    return loc

def sarif_finding(filename, query_vars):
    '''query_vars is a list that must contain [ruleid, level, message_format, locations, *finding_vars]'''
    # TODO: decide whether filename is still needed
    logger.debug(f'sarif_finding: {filename}, {query_vars!r}')
    rule_id = query_vars[0]
    level = query_vars[1]
    message = query_vars[2].format(*query_vars[4:])
    locations = [ sarif_location(*loc) for loc in query_vars[3] ]
    logger.debug(f'{locations=}')
    # TODO: kind
    result = Result(rule_id=rule_id, level=level, message=Message(text=message), locations=locations, kind=None)
    return result



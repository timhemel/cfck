import logging

import json
import bisect
from attrs import asdict
from attrs import has, fields
import cattrs
from cattrs.gen import make_dict_unstructure_fn, override
from sarif_om import SarifLog, Run, Tool, ToolComponent, Result, Location, PhysicalLocation, ArtifactLocation, ThreadFlowLocation, Region, ReportingDescriptor, Message, CodeFlow, ThreadFlow

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
        for finding_vars in iterator:
            self.sarif_log = self.render_func(self.sarif_log, filename, finding_vars)

    def add_rules(self):
        for run in self.sarif_log.runs:
            rule_ids = sorted(set(result.rule_id for result in run.results))
            run.tool.driver.rules = [ ReportingDescriptor(id=rid, name=rid) for rid in rule_ids ]
            for result in run.results:
                rule_index = bisect.bisect_left(rule_ids, result.rule_id)
                result.rule_index = rule_index

    def end(self):
        self.add_rules()
        renamed_log = clear_none_values(converter.unstructure(self.sarif_log))
        print(json.dumps(renamed_log))


def sarif_location(path, startloc, endloc, message=None):
    logger.debug(f'sarif_location: {path=}, {startloc=}, {endloc=}')
    region = Region(start_line=startloc[0], start_column=startloc[1], end_line=endloc[0], end_column=endloc[1], byte_offset=None, char_offset=None)
    artifact_location = ArtifactLocation(uri=path, index=None, uri_base_id='%SRCROOT%')
    phys_loc = PhysicalLocation(artifact_location=artifact_location, region=region)
    loc = Location(id=None, physical_location=phys_loc, message=message)
    logger.debug(f'sarif_location: {loc=}')
    return loc

def sarif_finding(sarif_log, filename, query_vars):
    ''' OBSOLETE.
    query_vars is a list that must contain [ruleid, level, message_format, locations, *finding_vars]'''
    # TODO: decide whether filename is still needed
    logger.debug(f'sarif_finding: {filename}, {query_vars!r}')
    rule_id = query_vars[0]
    level = query_vars[1]
    try:
        message = query_vars[2].format(*query_vars[4:])
    except KeyError:
        message = query_vars[2]
    locations = [ sarif_location(*loc) for loc in query_vars[3] ]
    logger.debug(f'{locations=}')
    # TODO: kind
    result = Result(rule_id=rule_id, level=level, message=Message(text=message), locations=locations, kind=None)
    return result

def sarif_update_toolname(sarif_log, values):
    sarif_log.runs[0].tool.driver.name = values[0]
    return sarif_log

def sarif_update_toolversion(sarif_log, values):
    sarif_log.runs[0].tool.driver.version = values[0]
    return sarif_log

def sarif_update_ruleid(sarifresult, values):
    '''ruleid(RuleId), where RuleId is a string'''
    sarifresult.rule_id = values[0]
    return sarifresult

def sarif_update_level(sarifresult, values):
    '''level(Level), where Level is a string representing a valid SARIF level'''
    sarifresult.level = values[0]
    return sarifresult

def sarif_update_kind(sarifresult, values):
    '''kind(Kind), where Kind is a string representing a valid SARIF kind'''
    sarifresult.kind = values[0]
    return sarifresult

def sarif_update_message(sarifresult, values):
    '''message(Message,Args), where Message is a message template containing placeholders, in which the values of Args are substituted'''
    # TODO: support more complex message formats (templates, markdown, etc)
    try:
        text = values[0].format(*values[1])
    except KeyError:
        text = values[0]
    except ValueError:
        text = values[0]
    sarifresult.message = Message(text=text)
    return sarifresult

def sarif_update_locations(sarifresult, values):
    '''locations(Locations), where Locations is a list of lists:
    [ [FileName,[StartLine,StartCol],[EndLine,EndCol]], ... ]
    '''
    logger.debug(f'sarif_update_locations: {values[0]=}')
    sarifresult.locations = [ sarif_location(*loc) for loc in values[0] ]
    return sarifresult

def sarif_update_codeflow(sarifresult, values):
    '''codeflow(Locations), where Locations is a list of lists:
    [ [[FileName,[StartLine,StartCol],[EndLine,EndCol]], Message], ... ]

    Only supports one codeflow, with one threadflow. To add more flows, use
    this functor more than once. Supports messages with the locations.
    '''
    locations = [ ThreadFlowLocation(execution_order=None, importance=None, index=None,
            location=sarif_location(*loc, message=Message(text=msg))) for loc,msg in values[0] ]
    threadflow = ThreadFlow(locations=locations)
    if sarifresult.code_flows is None:
        sarifresult.code_flows = []
    sarifresult.code_flows.append(CodeFlow(thread_flows = [threadflow]))
    return sarifresult

sarif_log_updater = {
        'toolname': sarif_update_toolname,
        'toolversion': sarif_update_toolversion,
}

sarif_result_updater = {
        'ruleid': sarif_update_ruleid,
        'message': sarif_update_message,
        'locations': sarif_update_locations,
        'kind': sarif_update_kind,
        'level': sarif_update_level,
        'codeflow': sarif_update_codeflow,
}


def structured_sarif_finding(sarif_log, filename, query_vars):
    '''query_vars is a list that contains functors'''
    # TODO: decide whether filename is still needed
    logger.debug(f'structured_sarif_finding: {filename}, {query_vars!r}')
    result = Result(message=None)
    for qv in query_vars:
        if isinstance(qv,tuple):
            key,values = qv
            try:
                log_upd = sarif_log_updater[key]
                sarif_log = log_upd(sarif_log, values)
            except KeyError:
                pass
            try:
                res_upd = sarif_result_updater[key]
                result = res_upd(result, values)
            except KeyError:
                logger.warn(f'structured_sarif_finding: no handler for key {key}')
        else:
            logger.warn(f'structured_sarif_finding: do not know how to handle query_value {qv!r}')
    logger.debug(f'structured_sarif_finding: appending result {result}')
    if result.message is not None:
        sarif_log.runs[0].results.append(result)
    return sarif_log


def structured_sarif_finding(sarif_log, filename, query_vars):
    '''query_vars is a list that contains functors'''
    # TODO: decide whether filename is still needed
    logger.debug(f'structured_sarif_finding: {filename}, {query_vars!r}')
    result = Result(message=None)
    for qv in query_vars:
        if isinstance(qv,tuple):
            key,values = qv
            try:
                log_upd = sarif_log_updater[key]
                sarif_log = log_upd(sarif_log, values)
            except KeyError:
                pass
            try:
                res_upd = sarif_result_updater[key]
                result = res_upd(result, values)
            except KeyError:
                logger.warn(f'structured_sarif_finding: no handler for key {key}')
        else:
            logger.warn(f'structured_sarif_finding: do not know how to handle query_value {qv!r}')
    logger.debug(f'structured_sarif_finding: appending result {result}')
    if result.message is not None:
        sarif_log.runs[0].results.append(result)
    return sarif_log


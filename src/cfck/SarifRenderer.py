import logging

import json
from attrs import asdict
from sarif_om import SarifLog, Run, Tool, ToolComponent, Result, PhysicalLocation, ArtifactLocation, Region

from .BaseRenderer import BaseRenderer

logger = logging.getLogger(__name__)

class SarifRenderer(BaseRenderer):

    def __init__(self, render_func):
        super().__init__(render_func)
        self.sarif_log = None

    def begin(self):
        run = Run(tool=Tool(driver=ToolComponent(name='cfck',version='0.0.1')), results=[])
        self.sarif_log = SarifLog(runs=[run],version='2.1.0')

    def feed(self, filename, iterator):
        self.sarif_log.runs[0].results += [ self.render_func(filename, finding_vars) for finding_vars in iterator ]

    def end(self):
        #print(self.sarif_log)
        print(json.dumps(asdict(self.sarif_log, filter=(lambda a,v: (v is not None)))))

def sarif_location(path, startloc, endloc):
    region = Region(start_line=startloc[0], start_column=startloc[1], end_line=endloc[0], end_column=endloc[1], byte_offset=None, char_offset=None)
    artifact_location = ArtifactLocation(uri=path, index=None)
    loc = PhysicalLocation(artifact_location=artifact_location, region=region)
    return loc

def sarif_finding(filename, query_vars):
    '''query_vars is a list that must contain [ruleid, level, message_format, locations, *finding_vars]'''
    # TODO: decide whether filename is still needed
    logger.debug(f'sarif_finding: {filename}, {query_vars!r}')
    rule_id = query_vars[0]
    level = query_vars[1]
    message = query_vars[2].format(*query_vars[4:])
    locations = [ sarif_location(*loc) for loc in query_vars[3] ]
    # TODO: kind
    result = Result(rule_id=rule_id, level=level, message=message, locations=locations, kind=None)
    return result



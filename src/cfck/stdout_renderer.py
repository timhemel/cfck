import logging
from .BaseRenderer import BaseRenderer

logger = logging.getLogger(__name__)

def sarif_importance(kind, level):
    if level in ['error','warning','note']:
        return level
    if kind in ['informational','notApplicable','pass']:
        return 'note'
    if kind in ['open','review']:
        return 'warning'
    return 'warning'


def structured_quickfix_finding(filename, query_vars):
    '''query_vars is a list that contains functors'''
    qv_dict = dict(query_vars)
    logger.debug(f'structured_quickfix_finding: {filename}, {qv_dict}')
    rule_id = qv_dict.get('ruleid',['missing_rule'])[0]
    level = qv_dict.get('level',[''])[0]
    kind = qv_dict.get('kind',[''])[0]
    importance = sarif_importance(kind, level)

    message = qv_dict.get('message',('',[])) # format(*query_vars[4:])
    try:
        message_string = message[0].format(*message[1])
    except KeyError:
        message_string = message[0]
    except ValueError:
        message_string = message[0]
    logger.debug(f'structured_quickfix_finding: locs = {qv_dict.get("locations")}')
    locs = qv_dict.get('locations', [[]])[0]
    locations = [ f'{path}:{startloc[0]}:{startloc[1]}' for path, startloc, endloc in locs ]
    if locations == []:
        return None  # No use reporting quickfix without location
    return f'{locations[0]}:{importance}:{rule_id}:{message_string}'

def render_plain(filename, finding_vars):
    # line = finding_vars[1].sourceline
    logger.debug(f'render_plain: {filename=}, {finding_vars=}')
    message = finding_vars[0].format(*finding_vars[1:])
    return message


class StdoutRenderer(BaseRenderer):

    def feed(self, filename, iterator):
        for finding_vars in iterator:
            s = self.render_func(filename, finding_vars)
            if s is not None:
                self.write(s,end='\n')



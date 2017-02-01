import ipaddress
import logging
import json
from FirewallTools.common import RuleType
from FirewallTools import Rule
from FirewallTools.common import FirewallProtocols

class RuleParser(object):
    def __init__(self, filename):
        self.filename = filename
        self.rules=[]
        self.logger = logging.getLogger('Controller.{0}'.format(self.__class__.__name__))
        
        with open(filename) as rulefile:
            rulelist = json.load(rulefile)
            for rule in rulelist:
                if self.add_rule(rule):
                    self.logger.info("Rule parsed successfully.")
                else:
                    self.logger.error("Rule parsing aborted, fix your rule file.")
                    break


    def add_rule(self, ruleDict):
        try:
            rule_type = RuleType[ruleDict['type']]
            fields = {}
            if 'fields' in ruleDict:
                fields = ruleDict['fields']
            description = None
            if 'description' in ruleDict:
                description = ruleDict['description']
            self.logger.debug('Loading rule "{0}"'.format(description))
            inverse = False
            if 'inverse' in ruleDict:
                inverse = ruleDict['inverse']

            protocol_dict = {}
            for proto in ruleDict['protocols']:
                self.logger.debug('Found filter for protocol: {0}'.format(proto))
                key = FirewallProtocols[proto.upper()]
                value = ruleDict['protocols'][proto]
                if 'inverse' not in value:
                    value['inverse'] = False
                else:
                    value['inverse'] = bool(value['inverse'])
                if key == FirewallProtocols.IPV4:
                    # IPv4 fields
                    if 'ipv4_dst' in value:
                        value['ipv4_dst'] = ipaddress.IPv4Network(value['ipv4_dst'],strict=False)  
                    else:
                        value['ipv4_dst'] = None
                    if 'ipv4_src' in value:
                        value['ipv4_src'] = ipaddress.IPv4Network(value['ipv4_src'],strict=False)  
                    else:
                        value['ipv4_src'] = None

                if key == FirewallProtocols.TCP or key == FirewallProtocols.UDP:
                    # TCP/UDP fields
                    if 'tcp_src' not in value:                        
                        value['tcp_src'] = None
                    if 'tcp_dst' not in value:
                        value['tcp_dst'] = None

                protocol_dict[key] = value 

            rule = Rule(rule_type,protocol_dict,description=description,inverse=inverse,fields=fields)
            self.rules.append(rule)
        except KeyError as ke:
            self.logger.error("Error in parsing rule, skipping (%s).",ke)            
            return False
        else:
            return True

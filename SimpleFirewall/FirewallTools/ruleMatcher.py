import logging
from FirewallTools.common import RuleType
from FirewallTools.common import ActionType

class RuleMatcher(object):
    def __init__(self, parser):
        self.parser = parser
        self.logger = logging.getLogger('Controller.{0}'.format(self.__class__.__name__))


    def match(self, packet):
        for rule in self.parser.rules:
            self.logger.debug("Running rule {0}".format(rule.description))
            (result, packet_data) = rule.match(packet)
            if result:
                return (rule, packet_data, self.ruleTypeToAction(rule.ruleType))
        return (None,None,ActionType.FALLBACK)

    def ruleTypeToAction(self, rType: RuleType) -> ActionType:
        if rType == RuleType.DROP:
            return ActionType.DROP
        if rType == RuleType.PASS:
            return ActionType.PASS
        if rType == RuleType.MODIFY:
            return ActionType.MODIFY

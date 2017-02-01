"""
This is a Basic L2 Switch that turned into a somewhat malicious firewall. (To be fair normal firewalls can also do this, but they mostly are not SDN for increased security, and changing packets is not really a thing they should do.)
"""
import logging

import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import ryu.utils as ryuutils

import FirewallTools # __main__ case

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

import pprint
pp = pprint.PrettyPrinter(indent=4)

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    LOGGER_NAME = "Controller"

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        globallogger = logging.getLogger()
        globallogger.handlers = []
        self.logger.setLevel(logging.INFO)
        
        # create formatter and add it to all handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s',datefmt="%H:%M:%S")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        
        # add the handler to the logger    
        #self.logger.addHandler(handler) 
        globallogger.addHandler(handler)   
        
        self.logger.info('Started controller.')
        self.matcher = FirewallTools.RuleMatcher(FirewallTools.RuleParser(os.path.join(SCRIPT_DIR,'firewall-rules.json')))
        self.logger.info('Initialized the Rule Matching engine.')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        self.logger.debug("Add flow result: {0} for actions {1}".format(datapath.send_msg(mod),actions))
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        #Send it to packet matcher
        (rule_matched, packet_data, rule_action) = self.matcher.match(pkt)
        
        if rule_matched is not None:
            self.logger.info("The result of the matcher was {0} on the rule {1}".format(rule_action, rule_matched.description))
        else:
            self.logger.info("Not one rule was matched, using {0} action.".format(rule_action))

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        orig_dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if rule_action == FirewallTools.common.ActionType.DROP:
            self.logger.debug("Dropping packet %s %s %s %s", dpid, src, dst, in_port)
        elif rule_action == FirewallTools.common.ActionType.PASS:
            self.logger.debug("Passing packet %s %s %s %s", dpid, src, dst, in_port)
        elif rule_action == FirewallTools.common.ActionType.MODIFY:
            self.logger.debug("Fields to modify: %s",pp.pformat(rule_matched.fields))
            if 'eth_dst' in rule_matched.fields:
                self.logger.debug("Setting destination from %s to %s",dst, rule_matched.fields['eth_dst'])
                dst = rule_matched.fields['eth_dst']
            self.logger.debug("Modifying packet %s %s %s %s", dpid, src, dst, in_port)
        else:
            self.logger.debug("Dropping packet %s %s %s %s (fallback)", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = []
        if rule_action == FirewallTools.common.ActionType.MODIFY:
            for field in rule_matched.fields:
                actions.append(parser.OFPActionSetField(**{field: rule_matched.fields[field]}))
            actions.append(parser.OFPActionOutput(out_port))
        elif rule_action == FirewallTools.common.ActionType.DROP:
            pass
        elif rule_action == FirewallTools.common.ActionType.PASS:
            actions.append(parser.OFPActionOutput(out_port))
            
        
        self.logger.debug("Actions to perform: %s", pp.pformat(actions))

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if rule_matched is not None and len(packet_data) > 0:
                match_data = rule_matched.to_opfmatch_data(packet_data=packet_data,in_port=in_port, eth_dst=orig_dst)
                match = parser.OFPMatch(**match_data)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                self.logger.debug("Had buffer ID")
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                self.logger.debug("Had no buffer ID")
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _error_msg_handler(self, ev):
        msg = ev.msg

        ofp = msg.datapath.ofproto
        (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
        self.logger.error('EventOFPErrorMsg received.')
        self.logger.error(
            'version=%s, msg_type=%s, msg_len=%s, xid=%s', hex(msg.version),
            hex(msg.msg_type), hex(msg.msg_len), hex(msg.xid))
        self.logger.error(
            ' `-- msg_type: %s', ofp.ofp_msg_type_to_str(msg.msg_type))
        self.logger.error(
            "OFPErrorMsg(type=%s, code=%s, data=b'%s')", hex(msg.type),
            hex(msg.code), ryuutils.binary_str(msg.data))
        self.logger.error(
            ' |-- type: %s', ofp.ofp_error_type_to_str(msg.type))
        self.logger.error(
            ' |-- code: %s', ofp.ofp_error_code_to_str(msg.type, msg.code))
        self.logger.error(
            ' `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s',
            hex(version), hex(msg_type), hex(msg_len), hex(xid))
        self.logger.error(
            '     `-- msg_type: %s', ofp.ofp_msg_type_to_str(msg_type))
        
        
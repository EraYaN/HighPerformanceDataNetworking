import logging
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from FirewallTools.common import FirewallProtocols
from FirewallTools.common import map_protocols
import FirewallTools.protocol as protocols

class Rule(object):
    def __init__(self, ruleType, data, description=None, inverse=False, fields={}):
        self.ruleType = ruleType
        self.data = data
        self.fields = fields
        self.description = description
        self.inverse = inverse
        self.logger = logging.getLogger('Controller.{0}'.format(self.__class__.__name__))
        self.logger.debug(self.data)

    def match(self, pkt):
        results = []
        packet_data = {}

        self.logger.debug("Packet: {0}".format(pkt))
        for proc_data in pkt:
            try:
                proto = map_protocols(proc_data)
                self.logger.debug("Found protocol {0} in packet, parsed to {1}".format(proc_data.protocol_name,proto))
            except AttributeError:
                continue
            
            if proto != FirewallProtocols.UNKNOWN:
                packet_data[proto] = proc_data
            if proto in self.data and proto != FirewallProtocols.UNKNOWN:
                
                subrule = self.data[proto]
                self.logger.debug("Trying rule for {0} - {1}".format(proto,subrule))
                if proto == FirewallProtocols.IPV4:                    
                    int_res = protocols.IPv4.match(proc_data,dst=subrule['ipv4_dst'],src=subrule['ipv4_src'])
                    self.logger.debug("IPv4 part result: {0}".format(int_res if not subrule['inverse'] else not int_res))
                elif proto == FirewallProtocols.TCP:
                    int_res = protocols.TCP.match(proc_data,tcp_dst=subrule['tcp_dst'],tcp_src=subrule['tcp_src'])
                    self.logger.debug("TCP part result: {0}".format(int_res if not subrule['inverse'] else not int_res))
                elif proto == FirewallProtocols.UDP:
                    int_res = protocols.UDP.match(proc_data,tcp_dst=subrule['tcp_dst'],tcp_src=subrule['tcp_src'])
                    self.logger.debug("UDP part result: {0}".format(int_res if not subrule['inverse'] else not int_res))
                elif proto == FirewallProtocols.ICMP:
                    int_res = protocols.ICMP.match(proc_data)
                    self.logger.debug("ICMP part result: {0}".format(int_res if not subrule['inverse'] else not int_res))
                else:
                    # Configuration error, skip
                    continue

                if subrule['inverse']:
                    results.append(not int_res)
                else:
                    results.append(int_res)    
        MatchedCount = results.count(True)
        self.logger.debug("This {} should match {} and {}".format(MatchedCount,len(results),len(self.data)))
        if self.inverse:
            return (not (MatchedCount == len(results) and MatchedCount == len(self.data)), packet_data)
        else:
            return (MatchedCount == len(results) and MatchedCount == len(self.data), packet_data)
    
    def to_opfmatch_data(self, packet_data, eth_dst, in_port):
        
        result = {'eth_dst':eth_dst,'in_port':in_port}
        for proto in self.data:
            subrule = self.data[proto]
            if proto == FirewallProtocols.IPV4 and proto in packet_data:  
                result['eth_type'] = 0x0800 # value fo IPv4, IPv6 is 0x86dd
                if subrule['ipv4_src']:
                    result['ipv4_src'] = packet_data[proto].src
                if subrule['ipv4_dst'] is not None:
                    result['ipv4_dst'] = packet_data[proto].dst
            elif proto == FirewallProtocols.TCP:
                if 'eth_type' not in result:
                    result['eth_type'] = 0x0800 # value fo IPv4, IPv6 is 0x86dd
                result['ip_proto'] = 6
                if subrule['tcp_src'] is not None:
                    result['tcp_src'] = packet_data[proto].src_port
                if subrule['tcp_dst'] is not None:
                    result['tcp_dst'] = packet_data[proto].dst_port
            elif proto == FirewallProtocols.UDP:
                if 'eth_type' not in result:
                    result['eth_type'] = 0x0800 # value fo IPv4, IPv6 is 0x86dd
                result['ip_proto'] = 17
                if subrule['udp_src'] is not None:
                    result['udp_src'] = packet_data[proto].src_port
                if subrule['udp_dst'] is not None:
                    result['udp_dst'] = packet_data[proto].dst_port
            elif proto == FirewallProtocols.ICMP:
                if 'eth_type' not in result:
                    result['eth_type'] = 0x0800 # value fo IPv4, IPv6 is 0x86dd
                #if 'ipv4_src' not in result:
                #    result['ipv4_src'] = packet_data[FirewallProtocols.IPV4].src
                #if 'ipv4_dst' not in result:
                #    result['ipv4_dst'] = packet_data[FirewallProtocols.IPV4].dst
                result['ip_proto'] = 1
            else:
                # Configuration error, skip
                continue
        self.logger.debug("Packet Data: ",packet_data)
        self.logger.debug("Match Rule: ",result)
        return result



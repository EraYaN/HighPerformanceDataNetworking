from enum import Enum, unique

@unique
class RuleType(Enum):
    DROP = 1
    PASS = 2
    MODIFY = 3

@unique
class ActionType(Enum):
    FALLBACK = 0
    DROP = 1
    PASS = 2
    MODIFY = 3

@unique
class FirewallProtocols(Enum):
    UNKNOWN = 0
    IPV4 = 1
    TCP = 2
    UDP = 3
    ICMP = 4


from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
def map_protocols(proto):
    if type(proto) is ipv4.ipv4:
        return FirewallProtocols.IPV4
    if type(proto) is tcp.tcp:
        return FirewallProtocols.TCP
    if type(proto) is udp.udp:
        return FirewallProtocols.UDP
    if type(proto) is icmp.icmp:
        return FirewallProtocols.ICMP
    return FirewallProtocols.UNKNOWN

def map_protocols_reverse(proto):
    if proto == FirewallProtocols.IPV4:
        return ipv4.ipv4
    if proto == FirewallProtocols.TCP:
        return tcp.tcp
    if proto == FirewallProtocols.UDP:
        return udp.udp
    if proto == FirewallProtocols.ICMP:
        return icmp.icmp
    return None

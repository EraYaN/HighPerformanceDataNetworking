import ipaddress
from . import ProtocolBase
from ryu.lib.packet import ipv4

class IPv4(ProtocolBase):
    @staticmethod
    def match(v4data, src=None, dst=None):   
        if src is None and dst is None:  
            return True
        if src is None:
            return (ipaddress.IPv4Address(v4data.dst) in dst)
        elif dst is None:
            return (ipaddress.IPv4Address(v4data.src) in src)
        else:
            return (ipaddress.IPv4Address(v4data.src) in src) and (ipaddress.IPv4Address(v4data.dst) in dst)

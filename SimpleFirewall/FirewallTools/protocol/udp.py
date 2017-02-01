from . import ProtocolBase
from ryu.lib.packet import udp

class UDP(ProtocolBase):
    @staticmethod
    def match(udpdata, udp_src=None, udp_dst=None):   
        if udp_src is None and udp_dst is None:  
            return True
        if udp_src is None:
            return udpdata.dst_port == udp_dst
        elif udp_dst is None:
            return udpdata.src_port == udp_src
        else:
            return udpdata.src_port == udp_src and udpdata.dst_port == udp_dst
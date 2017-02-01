from . import ProtocolBase
from ryu.lib.packet import tcp

class TCP(ProtocolBase):
    @staticmethod
    def match(tcpdata, tcp_src=None, tcp_dst=None):   
        if tcp_src is None and tcp_dst is None:  
            return True
        if tcp_src is None:
            return tcpdata.dst_port == tcp_dst
        elif tcp_dst is None:
            return tcpdata.src_port == tcp_src
        else:
            return tcpdata.src_port == tcp_src and tcpdata.tcp_dst == dst_port
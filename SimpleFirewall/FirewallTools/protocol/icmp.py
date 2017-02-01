from . import ProtocolBase

class ICMP(ProtocolBase):
    @staticmethod
    def match(icmpdata):   
        return True
class ProtocolBase(object):
    @staticmethod
    def check_data(data):
        return True
    
    @staticmethod
    def match(data, packet):
        return True
        
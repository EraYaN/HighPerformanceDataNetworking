#!/usr/bin/python
"""
Basic Firewall topology and tests

"""
import time
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from functools import partial


from mininet.node import Controller
import os

PROTOCOL = 'OpenFlow13'

class FirewallTestTopo( Topo ):
    "Topology for a basic Firewall Test."

    def build( self ):        
        # Create switches and hosts
        srv = self.addHost('srv',mac='00:00:00:00:00:01',ip='10.0.0.1')
        clt = self.addHost('clt',mac='00:00:00:00:00:02',ip='10.0.0.2')
        pxy = self.addHost('pxy',mac='00:00:00:00:00:03',ip='10.0.0.3')
        s1 = self.addSwitch('s1')

        # Wire up switches & hosts
        
        self.addLink( srv, s1, port2=1 )
        self.addLink( clt, s1, port2=2 )
        self.addLink( pxy, s1, port2=3 )   

topos = {'firewalltesttopo': FirewallTestTopo}

def dumpflows(ent,switch='s1'):
    print("Dumping flows for {}".format(switch))
    print(ent.cmd('ovs-ofctl -O {1} dump-flows {0}'.format(switch,PROTOCOL)))

def firewallTests(net):
    "Test a basic Firewall network"  
    http_server = None  
    http_proxy = None  
    try:
        s1 = net.switches[0]
        print("Starting Wireshark (Giving it 8 seconds to start)")
        s1.cmd('sudo -u mininet wireshark -i s1-eth1 -i s1-eth2 -i s1-eth3 -k &')
        time.sleep(8)
        print("Dumping host connections")
        dumpNodeConnections(net.hosts)
        dumpflows(s1)
        print("Testing network connectivity")
        net.pingAll()
        dumpflows(s1)
        print("Selecting hosts")
        print(net.hosts)
        http_server = net.getNodeByName('srv')
        http_client = net.getNodeByName('clt')
        http_proxy = net.getNodeByName('pxy')

        print("Starting HTTP server (Giving it 1 second to start)")
        print(http_server.cmd("python -m SimpleHTTPServer 80 >& /tmp/http.log &"))   
        time.sleep(1)
        print("Starting HTTP proxy (Giving it 1 second to start)")
        print(http_proxy.cmd("python proxy2/FirewallProxy.py 80 >& /tmp/proxy2.log &"))   
        time.sleep(1)
        #print("Starting client request")   

        #print(http_client.cmd("wget -O - ",http_server.IP(),''))
        print("Starting firefox")   

        print(http_client.cmd("firefox ",http_server.IP()))
        
        #CLI(net)

        print("Stopping HTTP server")
        print(http_server.cmd("kill %python"))

        dumpflows(s1)
        print("Done")
    finally:
        if http_server is not None:
            print("HTTP Log")
            print(http_server.cmd("cat /tmp/http.log"))
        if http_proxy is not None:
            print("Proxy Log")
            print(http_proxy.cmd("cat /tmp/proxy2.log"))

    
if __name__ == '__main__':
    setLogLevel( 'info' )
    OVSSwitch13 = partial( OVSSwitch, protocols=PROTOCOL)

    net = Mininet(topo=FirewallTestTopo(),controller=partial( RemoteController, ip='127.0.0.1', port=6633 ), switch=OVSSwitch13, autoStaticArp=True, autoSetMacs=True)
    net.start()
    
    firewallTests(net)

    net.stop()
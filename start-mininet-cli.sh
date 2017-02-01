#!/bin/bash

sudo mn --custom SimpleFirewall/MiniNetTests.py --arp --mac --topo firewalltesttopo --controller=remote --switch=ovs,protocols=OpenFlow13 --test=cli

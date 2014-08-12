# SystemWall netfilter packet handler
#
# Copyright (C) 2014 Sebastian Biedermann and Jakub Szefer
#
# SystemWall script for handling packets off to Volatility framework for detecting
# process that is receiving SYN/ACK packets.  Each time a SYN/ACK packet is received,
# it is held until memory is inspected and packet is released or dropped.  Port number
# is passed to Volatility plugin to get back process name, then that is compared against a while list.
#
# This packet handler is modeled after:
# https://www.wzdftpd.net/redmine/projects/nfqueue-bindings/repository/entry/examples/rewrite.py
#

#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Sebastian Biedermann and Jakub Szefer
@license:      GNU General Public License 2.0
@contact:      biedermann@seceng.informatik.tu-darmstadt.de, jakub.szefer@yale.edu
@organization:
"""

# import struct
import sys, os
import nfqueue

from time import time
from socket import AF_INET, inet_ntoa
from dpkt import ip, tcp

def packethandler(i,payload):
        dt = time()

	# Get IP packet
	data = payload.get_data()
	pkt = ip.IP(data)

	# Print some packet info
        # print ""
	print ">> Got packet, saddr: " + str(inet_ntoa(pkt.src)) + ", sport: " + str(pkt.tcp.sport) + ", daddr: " + str(inet_ntoa(pkt.dst)) + ", dport: " + str (pkt.tcp.dport) + ", seq: " + str(pkt.tcp.seq)
        # print ""

	# Start volatility script to look for the application that matches the port number
	f = os.popen("python vol.py -l firewire://forensic1394//0 --profile=LinuxLinux-3_13_0-24-genericx64 linux_syswall --dport " + str(pkt.tcp.dport))
    	content = f.readlines()
	decision = content[-1].strip()
	print ">> Volatility plugin decision is: " + decision
	f.close()

	# Act on the decision about the packet
	if decision == 'accept':
          payload.set_verdict(nfqueue.NF_ACCEPT)
	elif decision == 'drop':
          payload.set_verdict(nfqueue.NF_DROP)
	else:
	  print ">> Unrecognized decision: " + decision + ", allowing packet..."
	  print ">> Dump content:"
	  print content
          payload.set_verdict(nfqueue.NF_ACCEPT)

	# Done with one packet
	print ">> Processed a packet in " + str(round((time() - dt), 2)) + "s"
	sys.stdout.flush()
	return 1

print ">> Started systemwall-pktqueue.py"
q = nfqueue.queue()

print ">> Setting callback function to process each packet"
q.set_callback(packethandler)

print ">> Registering on netfilter queue #0"
q.fast_open(0, AF_INET)

print ">> Trying to run.."
try:
	q.try_run()
except KeyboardInterrupt, e:
	print ">> Interrupted!"

print ">> Unbind from netfilter queue"
q.unbind(AF_INET)

print ">> Done."
q.close()


# SystemWall Volatility plugin
#
# Copyright (C) 2014 Sebastian Biedermann and Jakub Szefer
#
# This file is part of SystemWall prototype, it is based on lsof.py
# file which is part of Volatility.  Volatility information is below,
# this plugin is released under GPL, like rest of Volatility.
#

#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
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

import socket, time, math, hashlib
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_syswall(linux_pslist.linux_pslist):
    """SystemWwall Volatility plugin, return name of process corresponding to dport of incoming connection"""

    def __init__(self, config, *args, **kwargs):
	linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
	config.add_option('dport', default = 0,
	                  help = 'Destination port number of incoming connection',
	                  action = 'store', type = 'int')

    def calculate(self):
	linux_common.set_plugin_members(self)

	# Get list of tasks running
	init_task_addr = self.addr_space.profile.get_symbol("init_task")
	init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)
	tasks = init_task.tasks

	# Get info about each task's open file descriptors
	for task in tasks:
	    # Limit to checking for known applications in
	    # a limited range of PIDs, if app is not found there, packet will be denied
	    if task.pid > 8000 and task.pid < 9000:
	    # or check for just a specific PID
	    # if task.pid == 7053:
	        fds = task.files.get_fds()
	        max_fds = task.files.get_max_fds()

	        fds = obj.Object(theType = 'Array', offset = fds.obj_offset, vm = self.addr_space, targetType = 'Pointer', count = max_fds)

	        for i in range(max_fds):
                	if fds[i]:
                	    filp = obj.Object('file', offset = fds[i], vm = self.addr_space)
                	    yield (task, filp, i)

    # Abusing this fuction to do the matching between port number and process name
    def render_text(self, outfd, data):
        dt = time.time()

	target_dport = self._config.dport
	decision = 'drop'
	#debug.info("Looking for dport == " + str(target_dport))

	# Load process name whitelist
	whitelist = open("DummyWhiteList.txt").read().splitlines()

	# Optional checking of hash for for shell code, disable by default
        global already_done
        pagesize = 4096
        do_hash_checks = False
        do_expl_checks = False

	# Iterrate through open file descriptors to look for application
	# that has an open socket, than match port number to that socket,
	# and finally compare application name to white list.
        for (task, filp, i) in data:
 
           # Optionally generate hash over each executable
           if do_hash_checks:
                if str(task.comm) not in already_done:

                    already_done.append(str(task.comm))
                    for vma in task.get_proc_maps():

                        if vma.vm_file:

                            if "r-x" in str(vma.vm_flags):

                                fname = str(linux_common.get_path(task, vma.vm_file))

                                if str(task.comm) in fname and ".so" not in fname:

                                    proc_as = task.get_process_address_space()
                                    start = vma.vm_start
                                    pages = ""

                                    while start < vma.vm_end:
                                        pages = pages + proc_as.zread(start, pagesize)
                                        start = start + pagesize

                                    debug.info("SHA1 for " + str(task.comm) + " is " + str(hashlib.sha1(pages).hexdigest()))
                                    break

           # End if hash checks

           # Optionally generate hash and check stack and heap for 0x00 sequences (shellcode)
           if do_expl_checks:
                if str(task.comm) not in already_done:

                    already_done.append(str(task.comm))
                    bufpages = ""

                    for vma in task.get_proc_maps():

                        if vma.vm_file:

                            # first hash
                            if "r-x" in str(vma.vm_flags):

                                fname = str(linux_common.get_path(task, vma.vm_file))

                                if str(task.comm) in fname and ".so" not in fname:

                                    proc_as = task.get_process_address_space()
                                    start = vma.vm_start
                                    pages = ""

                                    while start < vma.vm_end:
                                        pages = pages + proc_as.zread(start, pagesize)
                                        start = start + pagesize

                                    debug.info("SHA1 for " + str(task.comm) + " is " + str(hashlib.sha1(pages).hexdigest()))

                        # heap
                        elif vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk:

                                proc_as = task.get_process_address_space()
                                start = vma.vm_start

                                while start < vma.vm_end:
                                    bufpages = bufpages + proc_as.zread(start, pagesize)
                                    start = start + pagesize
                        # stack
                        elif vma.vm_start <= task.mm.start_stack and vma.vm_end >= task.mm.start_stack:

                                proc_as = task.get_process_address_space()
                                start = vma.vm_start

                                while start < vma.vm_end:
                                    bufpages = bufpages + proc_as.zread(start, pagesize)
                                    start = start + pagesize

                    hexstr = ":".join("{:02x}".format(ord(c)) for c in bufpages)
                    if "90:90:90:90:90:90:90" in hexstr:
                        debug.info("Shellcode for " + str(task.comm) + " found.")
                    else:
                        debug.info("Shellcode for " + str(task.comm) + " not found.")

           # End if hash and shell code checks

           # See if open file is a socket
           if filp.f_op == self.addr_space.profile.get_symbol("socket_file_ops") or filp.dentry.d_op == self.addr_space.profile.get_symbol("sockfs_dentry_operations"):
                
                iaddr = filp.dentry.d_inode
                skt = self.SOCKET_I(iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = self.addr_space)
                
                # We are only checking TCP sockets
                if inet_sock.protocol in ("TCP"):

                    state = inet_sock.state if inet_sock.protocol == "TCP" else ""
                    family = inet_sock.sk.__sk_common.skc_family
                    
                    # We are only checking IPv4
                    if family == socket.AF_INET:
                            
                        saddr = inet_sock.src_addr
                        if "0.0.0.0" not in str(saddr): 

                            sport = inet_sock.src_port 
                            dport = inet_sock.dst_port 
                            daddr = inet_sock.dst_addr

        		    #debug.info("Timestamp " + str(round((time.time() - dt), 2)) + "s")
                            debug.info("Daddr: " + str(daddr) + ", dport: " + str(dport) + ", saddr: " + str(saddr) + ", sport: " + str(sport) + ", status: " + str(state) + ", name: " + str(task.comm) + ", pid: " + str(task.pid))

			    # The port we are looking for is the destination port of the SYN/ACK packet,
			    # but on the target computer that is the source port of the original SYN
			    # connection, hence compare target_dport (packet) with sport (target)
			    if target_dport == sport:
				if str(task.comm) in whitelist:
					decision = 'accept'
					break

           # End checking for sockets

	# End of for loop

	debug.info("Done in " + str(round((time.time() - dt), 2)) + "s")

	# Last thing printed is the decision, accept or drop
	print decision

    def SOCKET_I(self, inode):

        backsize = self.profile.get_obj_size("socket")
        addr = inode - backsize
        return obj.Object('socket', offset = addr, vm = self.addr_space)



#!/usr/bin/python
#
# Copyright (C) 2014 slacknux <slacknux@gmail.com>
# http://www.slacknux.net
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import signal
import socket
import struct
import sys
import time
from threading import Thread

#Waiting time for scanning (seconds)
waiting = 60
#IP range start
ipRangeS = '192.168.1.1'
#IP range end
ipRangeE = '192.168.1.255'
#Network interface
netInterface = 'wlan0'
#Path of the file containing the IP list of connected devices
pat = '%s/db/%s' % (os.path.split(os.path.abspath(__file__))[0], time.strftime('%m%d%Y'))


class TimeoutException(Exception):
	#Exception to raise on a timeout
	pass


def timeout(function):
	#Execute function and stop after 1 second
	#If function ends within that second, all its operations will be performed, else 'pass'
	def timeout_handler(signum, frame):
		raise TimeoutException

	signal.signal(signal.SIGALRM, timeout_handler)

	signal.alarm(1)

	try:
		function()
	except TimeoutException:
		#Return TimeoutException
		pass
	else:
		signal.alarm(0)


class HeYou(Thread):
	#Thread to read all replies
	def __init__ (self):
		Thread.__init__(self)

		try:
			timeout(arp_reply)
		except IOError:
			#No stop HeYou if we aren't still connected
			pass


def alert(msg):
	#Notification via notify osd
	import pynotify

	if not pynotify.init("HeYou"):
		sys.exit(1)

	uri = os.path.split(os.path.abspath(__file__))[0] + '/img/HeYou.png'

	n = pynotify.Notification('HeYou', msg, uri)

	if not n.show():
		sys.exit(1)


def arp_reply():
	while True:
		frame = sock.recv(4096)
		opcode = struct.unpack('!H', frame[20:22])[0]	#Operation
   		snd_ha = frame[22:28]				#Sender hardware address
		snd_pa = frame[28:32]				#Sender protocol address

		if opcode == 2:
			ipSaved = []

			output = open(pat, 'a+')
			for line in output:
				ipSaved.append(line[:-1])
			output.close()

			ip = '%d.%d.%d.%d' % struct.unpack('!4B', snd_pa)
			mac = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % struct.unpack('!6B', snd_ha)
			ipList.append(ip)

			if ip not in ipSaved:
				#If ip isn't in the file containing the IP list of connected devices
				#display the notification via notify osd
				msg ='IP:\t %s\nMAC:  %s' % (ip, mac)
				alert(msg)


while True:
	try:
		time.sleep(waiting)
	except TimeoutException:
		#No stop HeYou if we aren't still connected
		pass

	#List of IP addresses of connected devices
	ipList = []

	st = ipRangeS.rsplit('.', 1)
	en = int(ipRangeE.rsplit('.', 1)[1]) + 1

	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	sock.bind((netInterface, socket.SOCK_RAW))

	for i in range(int(st[1]), en):
		ip = ''.join([st[0], '.', str(i)])
		packet = [
				#Ethernet part
				struct.pack('!6B', *(0xff,) * 6),			#Target hardware address (broadcast)
				sock.getsockname()[4],					#Sender hardware address
				struct.pack('!H', 0x0806),				#Protocol type (ARP)
				#ARP part
				struct.pack('!H', 0x0001),				#Hardware type (ethernet)
				struct.pack('!H', 0x0800),				#Procol type (IPv4)
				struct.pack('!B', 0x0006),				#Hardware length
				struct.pack('!B', 0x0004),				#Protocol length
				struct.pack('!H', 0x0001),				#Operation (ARP request)
				sock.getsockname()[4],					#Sender hardware address
				struct.pack('!4B', *(0,) * 4),				#Sender protocol address
				struct.pack('!6B', *(0,) * 6),				#Target hardware address
				struct.pack('!4B', *[int(x) for x in ip.split('.')])	#Target protocol address
		]

		try:
			sock.send(''.join(packet))
			time.sleep(0.02)
		except IOError:
			#No stop HeYou if we aren't still connected
			pass

	heyou = HeYou()
	heyou.start()

	sock.close()

	#Update the file containing the IP list of connected devices
	#to avoid the notify osd notification after the first time
	output = open(pat, 'w')
	for ip in ipList:
		output.write(ip+'\n')
	output.close()

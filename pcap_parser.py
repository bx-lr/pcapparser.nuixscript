#converting pcaps
import struct

#converting timestamps
import datetime

#reading files
import sys
import os

#syncing and threading
from Queue import Queue
from threading import Thread
from collections import OrderedDict
import logging

import time

#workbench specific stuff
try:
    import nuix
    import nuix.Binary
    #print dir(nuix)
    #print dir(nuix.Binary)
    #print dir(currentCase)
except:
    pass


#
#try to make everything a string so that we dont have 
#problems interfacing with anything else
#


#
#objects for each capture/packet item
#todo: fix all naming conventions
#todo: put the ethernet crap in the right place
#todo: comment everything!
#
class Capture:
    def __init__(self, filename, data):
        self.filename = filename
        self.data = data
        self.is_global_header_parsed = False
        #when we add support for really big files
        #check this to see if we need to process
        #more of the file
        self.has_more = False

        #items in the global header
        self.magic = ''
        self.version_major = ''
        self.version_minor = ''
        self.thiszone = ''
        self.sigfigs = ''
        self.snaplen = ''
        self.network = ''

        #index for all frame headers (file offsets)
        self.frame_header_locs = []
        #index for all frames
        self.pcap_frame_headers = OrderedDict()
        #count of frames
        self.pcap_frames = 0

    def print_global_header(self):
        if self.is_global_header_parsed:
            print 'Global Header:'
            print 'magic:', self.magic
            print 'version_major:', self.version_major
            print 'version_minor:', self.version_minor
            print 'thiszone:', self.thiszone
            print 'sigfigs:', self.sigfigs
            print 'snaplen:', self.snaplen
            print 'network:', self.network
            print ''
        else:
            print 'Header not parsed!'
        return           

    def get_printable_global_header(self):
        header_string = 'Global Header\n'
        if self.is_global_header_parsed:
            header_string += 'magic: %s\n' % self.magic
            header_string += 'version_major: %s\n' % self.version_major
            header_string += 'version_minor: %s\n' % self.version_minor
            header_string += 'thiszone: %s\n' % self.thiszone
            header_string += 'sigfigs: %s\n' % self.sigfigs
            header_string += 'snaplen: %s\n' % self.snaplen
            header_string += 'network: %s\n\n' % self.network
        return header_string


    def process_global_header(self):
        magic = self.data[0:4]
        magic = '0x' + ''.join(format(n,'02X') for n in magic)
        if magic == '0xD4C3B2A1' or magic == '0xA1B2C3D4':
            swap = False
        else:
            return False
        if magic == '0xD4C3B2A1':
            swap = True
        version_major = self.data[4:6]
        version_major = '0x' + ''.join(format(n, '02X') for n in version_major)
        version_minor = self.data[6:8]
        version_minor = '0x' + ''.join(format(n, '02X') for n in version_minor)
        thiszone = self.data[8:12]
        thiszone = '0x' + ''.join(format(n, '02X') for n in thiszone)
        sigfigs = self.data[12:16]
        sigfigs = '0x' + ''.join(format(n, '02X') for n in sigfigs)
        snaplen = self.data[16:20]
        snaplen = '0x' + ''.join(format(n, '02X') for n in snaplen)
        network = self.data[20:24]
        network = '0x' + ''.join(format(n, '02X') for n in network)
        magic = do_swap(magic, swap)
        version_major = do_swap(version_major, swap)
        version_minor = do_swap(version_minor, swap)
        thiszone = do_swap(thiszone, swap)
        sigfigs = do_swap(sigfigs, swap)
        snaplen = do_swap(snaplen, swap)
        network = do_swap(network, swap)

        #update our header info
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.network = network
        self.is_global_header_parsed = True
        return 

    def walk_pcap_frame_headers(self, offset):
        frame_len = self.data[offset+12:offset+16]
        frame_len = '0x' + ''.join(format(n, '02X') for n in frame_len)
        #figure out if we need to byte swap
        swap = False
        if self.data[0] ==  212:
            swap = True
        frame_len = do_swap(frame_len, swap)
        #return the next starting point
        return int(frame_len)+16


    def process_pcap_frame_header_locs(self):
        frame_header_offset = 24
        while frame_header_offset < len(self.data):
            #
            #todo: start adding session information
            #
            offset = self.walk_pcap_frame_headers(frame_header_offset)
            self.frame_header_locs.append(frame_header_offset)
            frame_header_offset += offset
        self.pcap_frames = len(self.frame_header_locs)
        return 

    def process_pcap_packet(self, offset):
        #print 'offset:', offset

        ts_sec = self.data[offset:offset+4]
        ts_sec = '0x' + ''.join(format(n, '02X') for n in ts_sec)
        #print 'ts_sec', ts_sec
        ts_usec = self.data[offset+4:offset+8]
        ts_usec = '0x' + ''.join(format(n, '02X') for n in ts_usec)
        incl_len = self.data[offset+8:offset+12]
        incl_len = '0x' + ''.join(format(n, '02X') for n in incl_len)
        orig_len = self.data[offset+12:offset+16]
        orig_len = '0x' + ''.join(format(n, '02X') for n in orig_len)

        swap = False
        if self.data[0] ==  212:
            swap = True

        #convert the timestamp to string
        ts_sec = str(int(do_swap(ts_sec, swap)))
        #ts_sec = datetime.datetime.fromtimestamp(ts_sec).strftime('%A, %B %d, %Y at %I:%M:%S %p %Z Central Standard Time')
        #ts_sec = datetime.datetime.fromtimestamp(ts_sec).isoformat() + '.000Z'
        #convert the microseconds to string
        ts_usec = int(do_swap(ts_usec, swap))
        #ts_usec =  datetime.timedelta(microseconds=ts_usec)

        #get the packet length
        incl_len = do_swap(incl_len, swap)
        orig_len = do_swap(orig_len, swap)

        #+16 is the size of the frame header
        #print offset, int(orig_len)
        frame_data = get_frame_data(self.data, offset, int(orig_len)+16)
        frame_data = frame_data.split(' ')
        #print 'data:', frame_data

        pf = PcapFrame()
        pf.ts_sec = ts_sec
        pf.ts_usec = ts_usec
        pf.incl_len = incl_len
        pf.orig_len = orig_len
        pf.frame_data = frame_data
        self.pcap_frame_headers[offset] = pf
        #start parsing the packet contents
        #get_ethernet_frame(frame_data)
        pf.process_pcap_packet()
        return 

    def process_pcap_packet_threaded(self, queue):
        while not queue.empty():
            work = queue.get()
            self.process_pcap_packet(work)
            queue.task_done()
        return



class PcapFrame:
    def __init__(self):
        self.ts_sec = ''
        self.ts_usec = ''
        self.incl_len = ''
        self.orig_len = ''
        self.frame_data = ''
        self.has_ethernet = False

    def print_frame(self):
        print 'Pcap Frame:'
        print 'ts_sec:', self.ts_sec
        print 'ts_usec:', self.ts_usec
        print 'incl_len:', self.incl_len
        print 'orig_len:', self.orig_len
        print_hexdump(self.frame_data[:16])
        return

    def get_frame_string(self):
        frame_str = '\nPcap Frame:\n'
        frame_str += 'ts_sec: %s\n' % self.ts_sec
        frame_str += 'ts_usec: %s\n' % self.ts_usec
        frame_str += 'incl_len: %s\n' % self.incl_len
        frame_str += 'orig_len: %s\n' % self.orig_len
        frame_str += hexdump_string(self.frame_data[:16])
        return frame_str 

    def process_pcap_packet(self):
        self.ef = EthernetFrame()
        data = self.frame_data[16:]

        #todo: throw this in the ethernetframe object process_ethernet_packet function
        destination_mac = ':'.join(data[0:6])
        source_mac = ':'.join(data[6:12])
        packet_type = ''.join(data[12:14])
        if len(self.frame_data) > 30:
            self.ef.frame_data = self.frame_data[30:]
            self.ef.frame_header = self.frame_data[16:30]
            self.ef.destination_mac = destination_mac
            self.ef.source_mac = source_mac
            self.ef.packet_type = packet_type
        else:
            #some weird shit here
            return

        if packet_type == '0800':
            #ipv4
            self.ef.destination_mac = destination_mac
            self.ef.source_mac = source_mac
            self.ef.packet_type = packet_type
            self.has_ethernet = True
            self.ef.frame_header = self.frame_data[16:30]
            self.ef.process_ethernet_packet()
            #parse_ipv4(data[14:])

        elif packet_type == '86DD':
            #ipv6
            self.ef.destination_mac = destination_mac
            self.ef.source_mac = source_mac
            self.ef.packet_type = packet_type
            self.has_ethernet = True
            self.ef.frame_header = self.frame_data[16:30]
            self.ef.process_ethernet_packet()
            #parse_ipv6(data[14:])
        elif data[0] == '60':
            self.ef.packet_type = '86DD'
            self.ef.frame_data = data
            self.ef.process_ethernet_packet()
            #parse_ipv6(data)
        else:

            return


class EthernetFrame:
    def __init__(self):
        self.destination_mac = ''
        self.source_mac = ''
        self.packet_type = ''
        self.frame_data = ''
        self.frame_header = ''

    def print_frame(self):
        print 'Ethernet Frame:'
        print 'destination mac:', self.destination_mac
        print 'source mac:', self.source_mac
        print 'type:', self.packet_type
        print_hexdump(self.frame_header)
        return

    def get_frame_string(self):
        frame_str = '\nEthernet Frame:\n'
        frame_str += 'destination mac: %s\n' % self.destination_mac
        frame_str += 'source mac: %s\n' % self.source_mac
        frame_str += 'type: %s\n' % self.packet_type 
        frame_str += hexdump_string(self.frame_header)       
        return frame_str

    def print_frame_data(self):
        return hexdump_string(self.frame_data)

    def get_frame_data(self):
        return hexdump_string(self.frame_data)

    def process_ethernet_packet(self):
        if self.packet_type == '0800':
            self.ip_type = '4'
        if self.packet_type == '86DD':
            self.ip_type = '6'
        self.ip = InternetProtocol()
        self.ip.frame_header = self.frame_data
        self.ip.ip_type = self.ip_type
        self.ip.process_ip_packet()


class InternetProtocol:
    def __init__(self):
        self.frame_header = ''
        self.frame_data = ''
        self.ip_type = ''

        #ipv4 specific items
        self.ip_version = ''
        self.header_length = ''
        self.differentiated_services = ''
        self.total_length = ''
        self.identification = ''
        self.flags = ''
        self.fragment_offset = ''
        self.time_to_live = ''
        self.protocol = ''
        self.header_checksum = ''
        self.ip_source = ''
        self.ip_destination = ''

        #ipv6 specific items
        self.version = ''
        self.traffic_class = ''
        self.flow_label = ''
        self.payload_length = ''
        self.next_header = ''
        self.hop_limit = ''
        self.source = ''
        self.destination = ''

    def print_frame(self):
        if self.ip_type == '4':
            print 'IPV4 Packet:'
            print 'ip_version:', self.ip_version
            print 'header length:', self.header_length
            print 'differentiated_services:', self.differentiated_services
            print 'total_length:', self.total_length
            print 'identification:', self.identification
            print 'flags:', self.flags
            print '\treserved:', format(int(self.flags), '03b')[0]
            print '\tdont fragment:', format(int(self.flags), '03b')[1]
            print '\tmore fragments:', format(int(self.flags), '03b')[2]
            print 'fragment_offset:', self.fragment_offset
            print 'time_to_live:', self.time_to_live
            print 'protocol:', self.protocol
            print 'header_checksum:', self.header_checksum
            print 'ip_source:', self.ip_source
            print 'ip_destination:', self.ip_destination
            print_hexdump(self.frame_header)
            return
        elif self.ip_type == '6':
            print 'IPV6 Packet'
            print 'version:', self.version
            print 'traffic_class:', self.traffic_class
            print 'flow_label:', self.flow_label
            print 'payload_length:', self.payload_length
            print 'next_header:', self.next_header
            print 'hop_limit:', self.hop_limit
            print 'source:', self.source
            print 'destination:', self.destination
            print_hexdump(self.frame_header)
        else:
            print 'OH NOES'
            return

    def get_frame_string(self):
        if self.ip_type == '4':
            frame_str = '\nIPV4 Packet\n'
            frame_str += 'ip_version: %s\n' % self.ip_version
            frame_str += 'header length: %s\n' % self.header_length
            frame_str += 'differentiated_services: %s\n' % self.differentiated_services
            frame_str += 'total_length: %s\n' % self.total_length
            frame_str += 'identification: %s\n' % self.identification
            frame_str += 'flags: %s\n' % self.flags
            frame_str += '\treserved: %s\n' % format(int(self.flags), '03b')[0]
            frame_str += '\tdont fragment: %s\n' % format(int(self.flags), '03b')[1]
            frame_str += '\tmore fragments: %s\n' % format(int(self.flags), '03b')[2]
            frame_str += 'fragment_offset: %s\n' % self.fragment_offset
            frame_str += 'time_to_live: %s\n' % self.time_to_live
            frame_str += 'protocol: %s\n' % self.protocol
            frame_str += 'header_checksum: %s\n' % self.header_checksum
            frame_str += 'ip_source: %s\n' % self.ip_source
            frame_str += 'ip_destination: %s\n' % self.ip_destination
            frame_str += hexdump_string(self.frame_header)
            return frame_str
        elif self.ip_type == '6':
            frame_str = '\nIPV6 Packet\n'
            frame_str += 'version: %s\n' % self.version
            frame_str += 'traffic_class: %s\n' % self.traffic_class
            frame_str += 'flow_label: %s\n' % self.flow_label
            frame_str += 'payload_length: %s\n' % self.payload_length
            frame_str += 'next_header: %s\n' % self.next_header
            frame_str += 'hop_limit: %s\n' % self.hop_limit
            frame_str += 'ip_source: %s\n' % self.source
            frame_str += 'ip_destination: %s\n' % self.destination
            frame_str += hexdump_string(self.frame_header)
            return frame_str
        else:
            return 'OH NOES'

    def get_frame_data(self):
        return hexdump_string(self.frame_data)

    def process_ip_packet(self):
        if self.ip_type == '4':
            #todo: parse differentiated services
            #todo: checksum validation
            ip_data = self.frame_header
            self.ip_version = str((int(ip_data[0], 16) & 0xF0) >> 4)
            self.header_length = str((int(ip_data[0], 16) & 0x0F) * 4)

            #self.ipv4_header_length = 20
            self.frame_data = self.frame_header[int(self.header_length):]
            self.frame_header = self.frame_header[:int(self.header_length)]
            self.differentiated_services = str(bin(int(format(ip_data[1]), 16)).replace('0b', '0'))
            total_length = ip_data[2:4]
            self.total_length = str(int(''.join(total_length), 16))
            self.identification = ''.join(ip_data[4:6])
            self.flags = str(int(bin(int(format(ip_data[6]), 16)).replace('0b', '0')[:3], 2))
            self.fragment_offset = str(int(''.join(ip_data[6:8]), 16) & 0x1F)
            self.time_to_live = int(ip_data[8], 16)
            self.protocol = str(int(ip_data[9], 16))
    
            self.header_checksum = ''.join(ip_data[10:12])

            ip_source = ip_data[12:16]
            tmp = []
            for i in ip_source:
                tmp.append(str(int(i, 16)))
            self.ip_source = '.'.join(tmp)

            ip_destination = ip_data[16:20]
            tmp = []
            for i in ip_destination:
                tmp.append(str(int(i, 16)))
            self.ip_destination = '.'.join(tmp)
            
        elif self.ip_type == '6':
            #todo: parse traffic class
            #todo: parse flowlabel
            #print 'IPv6 data:', ip_data
            ip_data = self.frame_header
            ipv6_header_length = 40
            self.frame_data = self.frame_header[ipv6_header_length:]
            self.frame_header = self.frame_header[:ipv6_header_length]
            self.version = str((int(ip_data[0], 16) & 0xF0) >> 4)

            self.traffic_class = bin(int(format(''.join(ip_data[0:4])), 16)).replace('0b', '0')[4:12]

            self.flow_label = str(hex(0x00FFFFFFF &  int(''.join(ip_data[0:4]), 16)))

            self.payload_length = str(int(''.join(ip_data[4:6]), 16))
            self.next_header = str(int(ip_data[6], 16))
            self.protocol = self.next_header
            self.hop_limit = str(int(ip_data[7], 16))

            #get ipv6 source address
            source = ip_data[8:24]
            tmp = []
            for i in range(2, len(source)+2, 2):
                tmp.append(''.join(source[i-2:i]))
            self.source = ':'.join(tmp)


            #get ipv6 destination address
            destination = ip_data[24:40]
            tmp = []
            for i in range(2, len(destination)+2, 2):
                tmp.append(''.join(destination[i-2:i]))
            self.destination = ':'.join(tmp)
        else:
            print 'OH NOES'
            return

        if self.protocol == '17':
            #udp
            self.udp = UDP()
            self.udp.frame_header = self.frame_data
            self.udp.process_udp_packet()
            return
        elif self.protocol == '6':
            #tcp
            self.tcp = TCP()
            self.tcp.frame_header = self.frame_data
            self.tcp.process_tcp_packet()
            return
        else:
            return 


class UDP:
    def __init__(self):
        self.frame_header = ''
        self.frame_data = ''

        self.src_port = ''
        self.dst_port = ''
        self.packet_length = ''
        self.header_checksum = ''

    def get_frame_string(self):
        frame_str = '\nUDP Packet\n'
        frame_str += 'source port: %s\n' % self.src_port
        frame_str += 'destination port: %s\n' % self.dst_port
        frame_str += 'length: %s\n' % self.packet_length
        frame_str += 'checksum: %s\n' % self.header_checksum
        frame_str += hexdump_string(self.frame_header)
        return frame_str

    def print_frame(self):
        print 'UDP PACKET'
        print 'source port:', self.src_port
        print 'destination port:', self.dst_port
        print 'length:', self.packet_length
        print 'checksum:', self.header_checksum
        if len(udp_data[8:]) > 0:
            print 'hexdump:'
            print_hexdump(udp_data[8:])
        print ''
        return 

    def get_frame_data(self):
        return hexdump_string(self.frame_data)

    def process_udp_packet(self):
        #todo: validate checksum
        #todo: session information
        udp_data = self.frame_header
        self.frame_data = self.frame_header[8:]
        self.frame_header = self.frame_header[:8]
        self.src_port = str(int(''.join(udp_data[0:2]), 16))
        self.dst_port = str(int(''.join(udp_data[2:4]), 16))
        self.packet_length = str(int(''.join(udp_data[4:6]), 16))
        self.header_checksum = str(hex(int(''.join(udp_data[6:8]), 16)))
        return 

class TCP:
    def __init__(self):
        self.frame_header = ''
        self.frame_data = ''

        self.src_port = ''
        self.dst_port = ''
        self.sequence_num = ''
        self.ack_num = ''
        self.header_length = ''
        self.flags = ''
        self.flags_reserved = ''
        self.flags_nonce = ''
        self.flags_congestion_window = ''
        self.flags_ecn_echo = ''
        self.flags_urgent = ''
        self.flags_acknowledgment = ''
        self.flags_push = ''
        self.flags_reset = ''
        self.flags_syn = ''
        self.flags_fin = ''
        self.window_size = ''
        self.checksum = ''
        self.urgent_pointer = ''
        self.options = ''

    def get_frame_string(self):
        frame_str = '\nTCP Packet:\n'
        frame_str += 'source port: %s\n' % self.src_port
        frame_str += 'destination port: %s\n' % self.dst_port
        frame_str += 'sequence number: %s\n' % self.sequence_num
        frame_str += 'acknowledgement number: %s\n' % self.ack_num
        frame_str += 'header length: %s\n' % self.header_length
        frame_str += 'flags: %s\n' % self.flags
        frame_str += '\treserved: %s\n' % self.flags[0:3]
        frame_str += '\tnonce: %s\n' % self.flags[3]
        frame_str += '\tcongestion window: %s\n' % self.flags[4]
        frame_str += '\tecn-echo: %s\n' % self.flags[5]
        frame_str += '\turgent: %s\n' % self.flags[6]
        frame_str += '\tacknowledgment: %s\n' % self.flags[7]
        frame_str += '\tpush: %s\n' % self.flags[8]
        frame_str += '\treset: %s\n' % self.flags[9]
        frame_str += '\tsyn: %s\n' % self.flags[10]
        frame_str += '\tfin: %s\n' % self.flags[11]
        frame_str += 'window size: %s\n' % self.window_size
        frame_str += 'checksum: %s\n' % self.checksum
        frame_str += 'urgent pointer: %s\n' % self.urgent_pointer
        if int(self.header_length) > 20:
            frame_str += 'options: %s\n' % self.options
        frame_str += hexdump_string(self.frame_header)
        return frame_str

    def get_frame_data(self):
        return hexdump_string(self.frame_data)

    def print_frame(self):
        print 'TCP PACKET'
        print 'source port:', self.src_port
        print 'destination port:', self.dst_port
        print 'sequence number:', self.sequence_num
        print 'acknowledgement number:', self.ack_num
        print 'header length:', self.header_length
        print 'flags:', self.flags
        print '\treserved:', self.flags[0:3]
        print '\tnonce:', self.flags[3]
        print '\tcongestion window:', self.flags[4]
        print '\tecn-echo:', self.flags[5]
        print '\turgent:', self.flags[6]
        print '\tacknowledgment:', self.flags[7]
        print '\tpush:', self.flags[8]
        print '\treset:', self.flags[9]
        print '\tsyn:', self.flags[10]
        print '\tfin:', self.flags[11]
        print 'window size:', self.window_size
        print 'checksum:', self.checksum
        print 'urgent pointer:', self.urgent_pointer
        if int(self.header_length) > 20:
            print 'options:', self.options
        print_hexdump(self.frame_header)
        print ''
        return        

    def process_tcp_packet(self):
        #todo: validate checksum
        #todo: parse options
        #todo: get rel seq num
        #todo: get rel ack num
        tcp_data = self.frame_header

        self.src_port =  str(int(''.join(tcp_data[0:2]), 16))
        self.dst_port =  str(int(''.join(tcp_data[2:4]), 16))
        self.sequence_num = str(int(''.join(tcp_data[4:8]), 16))
        self.ack_num = str(int(''.join(tcp_data[8:12]), 16))
        self.header_length = str(((int(tcp_data[12], 16) & 0xF0) >> 4) * 4)
        self.flags = format((int(''.join(tcp_data[12:14]), 16) & 0x0FFF), '012b')
        self.flags_reserved = self.flags[0:3]
        self.flags_nonce = self.flags[3]
        self.flags_congestion_window = self.flags[4]
        self.flags_ecn_echo = self.flags[5]
        self.flags_urgent = self.flags[6]
        self.flags_acknowledgment = self.flags[7]
        self.flags_push = self.flags[8]
        self.flags_reset = self.flags[9]
        self.flags_syn = self.flags[10]
        self.flags_fin = self.flags[11]
        self.window_size = str(int(''.join(tcp_data[14:16]), 16))
        self.checksum = hex(int(''.join(tcp_data[16:18]), 16))
        self.urgent_pointer = str(int(''.join(tcp_data[18:20]), 16))
        if int(self.header_length) > 20:
            self.options = ''.join(tcp_data[20:int(self.header_length)])

        self.frame_data = self.frame_header[int(self.header_length):]
        self.frame_header = self.frame_header[:int(self.header_length)]

        return        
#
#end objects for each capture/packet type
#


#
#pretty printing crap
#
def get_printable_char(byte):
    if byte:
        bint = int(byte, 16)
        if ((bint < 127) and (bint > 32)):
            return chr(bint)
        else:
            return '.'
    else:
        return ''


def print_hexdump(data, start_addr=0):
    line_str = ''
    ascii_str = ''
    while (len(data)%16 != 0):
        data.append(None)

    for byte in data:
        ascii_str = ascii_str + get_printable_char(byte)
        if start_addr%16 == 0:
            line_str += format(start_addr, '06X') 
            if byte:
                line_str += ' ' + byte
            else:
                line_str ++ '   '
        elif start_addr%16 == 15:
            if byte:
                line_str += ' ' + byte
            else:
                line_str += '   '
            line_str += ' ' + '\t'+ ascii_str + '\n'
            ascii_str = ''
        else:
            if byte:
                line_str += ' ' + byte
            else:
                line_str += '   '
        start_addr = start_addr + 1
    print line_str


def hexdump_string(data, start_addr=0):
    line_str = ''
    ascii_str = ''
    while (len(data)%16 != 0):
        data.append(None)

    for byte in data:
        ascii_str = ascii_str + get_printable_char(byte)
        if start_addr%16 == 0:
            line_str += format(start_addr, '06X') 
            if byte:
                line_str += ' ' + byte
            else:
                line_str ++ '   '
        elif start_addr%16 == 15:
            if byte:
                line_str += ' ' + byte
            else:
                line_str += '   '
            line_str += ' ' + '\t'+ ascii_str + '\n'
            ascii_str = ''
        else:
            if byte:
                line_str += ' ' + byte
            else:
                line_str += '   '
        start_addr = start_addr + 1
    return line_str

#
#end pretty printing crap
#


#
#pcap file format parsing
#
def do_swap(item, swap):
    if swap:
        if len(item) == 10:
            item = int(item, 16)
            return str(struct.unpack("<I", struct.pack(">I", item))[0])
        if len(item) == 6: 
            item = int(item, 16)
            return str(struct.unpack("<H", struct.pack(">H", item))[0])
    else:
        return item

def get_frame_data(capture, offset, flen):
    data = capture[offset:offset+flen]
    data = ' '.join(format(n, '02X') for n in data)
    return data

#
#end pcap file format parsing
#


#
#get file data outside of workbench
#
def read_and_convert(q, results):
    while not q.empty():
        work = q.get()
        fd = open(work[1], 'rb')
        data = fd.read()
        fd.close()
        pcap_data = []
        for d in data:
            pcap_data.append(struct.unpack('B', d)[0])
        #print pcap_data[0:10]
        results[work[1]] = pcap_data
        q.task_done()
    return results

def get_pcap_data(files):
    q = Queue(maxsize=0)
    nthreads = min(50, len(files))
    results = {}
    for i in xrange(len(files)):
        q.put((i,files[i]))
    #start a thread for each file
    for i in xrange(nthreads):
        #print 'starting thread', i
        #logging.info('starting thread', i)
        worker = Thread(target=read_and_convert, args=(q,results))
        worker.setDaemon(True)
        worker.start()
    #wait for completion..
    q.join()
    return results

def get_dir_pcap(path):
    files = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if '.pcap' in file:
                files.append(os.path.join(r, file))
            if '.cap' in file:
                files.append(os.path.join(r, file))
    return files
#
#end get file data outside workbench
#

#
#get file data inside workbench
#
def wb_read_and_convert(q, results):
    while not q.empty():
        pcap_data = []
        work = q.get()
        item = work[1]
        size = item.fileSize
        bin = item.binary.getBinaryData()
        for byte in xrange(0, size):
            tmp = bin.read(byte)
            tmp = struct.pack('B', tmp)
            pcap_data.append(struct.unpack('B', tmp)[0])
        results[item.name] = pcap_data
        q.task_done()
        return results


def wb_get_pcap_data(items):
    #items = currentCase.search('mime-type:application/vnd.tcpdump.pcap')
    q = Queue(maxsize=0)
    nthreads = min(50, len(items))
    results = {}
    for i in xrange(len(items)):
        q.put((i, items[i]))
    for i in xrange(nthreads):
        worker = Thread(target=wb_read_and_convert, args=(q,results))
        worker.setDaemon(True)
        worker.start()
    q.join()
    return results
#
#end get file data inside workbench
#



class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                # An exception happened in this thread
                print(e)
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()



#
#real main()
#todo: make string of entire packet so we can pull out http addrs and crap
#todo: fix hexdump alignment
def process_and_dump(all_pcap_files, output_path):
    captures = []
    for k,v in all_pcap_files.iteritems():
        cap = Capture(k, v)
        captures.append(cap)
    evidence = []
    #doing object shit
    for cap in captures:
        #make simple unique folder 
        ctime = str(time.time())
        outdir = 'out_' + ctime
        outpath = output_path + '\\'+ cap.filename + '_' + outdir + '/'
        os.mkdir(outpath)
        evidence.append(outpath)
        print 'processing:', cap.filename
        cap.process_global_header()  
        cap.process_pcap_frame_header_locs()
        #print 'num packets', cap.pcap_frames
        q = Queue(maxsize=0)
        nthreads = min(50, len(cap.frame_header_locs))

        #block until all packets are processed
        for loc in cap.frame_header_locs:
            q.put(loc)
        pool = ThreadPool(nthreads)
        pool.map(cap.process_pcap_packet_threaded, (q,))
        pool.wait_completion()
            
        #todo: make this better
        nfiles =  len(cap.pcap_frame_headers)
        for k,v in cap.pcap_frame_headers.iteritems():
            #create files that can be ordered by name in wb 
            fname = '{0}'.format('%s' % str(cap.frame_header_locs.index(k)+1).zfill(len(str(nfiles)))) 
            fd = open(outpath + '%s.txt' % fname, 'wb')
            #print 'writing file: ' + str(k) + ' packet number: ' + str(cap.frame_header_locs.index(k)+1) 
            fd.write('k: ' + str(k) +  ' packet number: ' + str(cap.frame_header_locs.index(k)+1) + '\n')
            fd.write(v.get_frame_string())
            if v.has_ethernet:
                fd.write(v.ef.get_frame_string())
                #print v.ef.print_frame_data()
                fd.write( v.ef.ip.get_frame_string())
                if hasattr(v.ef.ip, 'udp'):
                    fd.write( v.ef.ip.udp.get_frame_string())
                    fd.write('\nUDP Packet Data:\n')
                    fd.write( v.ef.ip.udp.get_frame_data())
                elif hasattr(v.ef.ip, 'tcp'):
                    fd.write( v.ef.ip.tcp.get_frame_string())
                    fd.write('\nTCP Packet Data:\n')
                    fd.write( v.ef.ip.tcp.get_frame_data())
                else:
                    fd.write('\nFrame Data:')
                    fd.write( v.ef.ip.get_frame_data())

            else:
                if hasattr(v.ef, 'ip'):
                    fd.write( v.ef.ip.get_frame_string())
                    if hasattr(v.ef.ip, 'udp'):
                        fd.write( v.ef.ip.udp.get_frame_string())
                        fd.write('\nUDP Packet Data:\n')
                        fd.write( v.ef.ip.udp.get_frame_data())
                    elif hasattr(v.ef.ip, 'tcp'):
                        fd.write( v.ef.ip.tcp.get_frame_string())
                        fd.write('\nTCP Packet Data:\n')
                        fd.write( v.ef.ip.tcp.get_frame_data())
                    else:
                        fd.write('\nFrame Data:\n')
                        fd.write( v.ef.ip.get_frame_data())
                else:
                    fd.write( v.ef.get_frame_string())
                    fd.write('\nFrame Data:\n')
                    fd.write( v.ef.get_frame_data())
            fd.close()
    return evidence

#
#end real main()
#


#if __name__ == '__main__':
    #
    #outside of workbench we process a directory with .pcap or .cap files 
    #
#    files = get_dir_pcap(sys.argv[1])
#    all_pcap_files = get_pcap_data(files)
#    rmain(all_pcap_files)
#
#
#else:
#    print 'code removed'
    #
    #inside workbench we process all files in the case with the vnd.tcpdump.pcap mime type
    #
    #all_pcap_files = wb_get_pcap_data()
    #rmain(all_pcap_files)




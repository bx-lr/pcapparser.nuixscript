import logging
import struct
from nuix import Address
from nuix import Communication
from org.joda.time import DateTime


class SimpleAddress (Address):
    def __init__(self, personal, address):
      self._address = address
      self._personal = personal
    
    def getPersonal(self):
        return self._personal

    def getAddress(self):
        return self._address

    def getType(self):
        return "internet-mail"

    def toRfc822String(self):
        return self._address

    def toDisplayString(self):
        return self._address

    def equals(self, address):
        return address == self._address        

class SimpleCommunication (Communication):
    def __init__(self, date_time, from_addresses, to_addresses, cc_addresses, bcc_addresses):
        self._date_time = date_time
        self._from_addresses = from_addresses
        self._to_addresses = to_addresses
        self._cc_addresses = cc_addresses
        self._bcc_addresses = bcc_addresses

    def getDateTime(self):
        return self._date_time

    def getFrom(self):
        return self._from_addresses

    def getTo(self):
        return self._to_addresses

    def getCc(self):
        return self._cc_addresses

    def getBcc(self):
        return self._bcc_addresses


def nuixWorkerItemCallbackInit():
    return

def nuixWorkerItemCallback(worker_item):
    # Do interesting things here
    logging.basicConfig(filename='C:\\Users\\jmitchell01\\Desktop\\projects\\nuix\\pcap\\log.txt')
    #tmp = dir(worker_item)
    #logging.critical('%s\n' % (tmp))
    try:
        item = worker_item.getSourceItem()
        #logging.critical('here 1\n')
        #property_dictionary = worker_item.itemProperties()
        property_dictionary = {}
        communication = {}
        #logging.critical('here 2\n') 
        #tmp = dir(item)
        #logging.critical('%s\n' % (tmp)) 
        #cm =  item.getCustomMetadata()
        #tmp = dir(cm)
        #logging.critical('%s\n' % (tmp)) 

        pcap_data = []
        size = item.fileSize
        bin = item.binary.getBinaryData()
        for byte in xrange(0, size):
            tmp = bin.read(byte)
            tmp = struct.pack('B', tmp)
            pcap_data.append(struct.unpack('c', tmp)[0])
        #print pcap_data
        #logging.critical('here 3\n')
        pcap_data = ''.join(pcap_data)
        data = pcap_data.split('\n')

        date = 'UNKNOWN'
        s_mac = 'UNKNOWN'
        d_mac = 'UNKNOWN'
        s_ip = 'UNKNOWN'
        d_ip = 'UNKNOWN'
        for line in data:
            if line.find('ts_sec') > -1:
                date = line.replace('ts_sec: ', '')
            if line.find('destination mac:') > -1:
                d_mac = line.replace('destination mac: ', '')
            if line.find('source mac:') > -1:
                s_mac = line.replace('source mac: ', '')
            if line.find('ip_source:') > -1:
                s_ip = line.replace('ip_source: ', '')
            if line.find('ip_destination:') > -1:
                d_ip = line.replace('ip_destination: ', '')


        property_dictionary['Transmission Date'] = DateTime(int(date)*1000)
        #property_dictionary['File Accessed'] = DateTime(int(date)*1000)
        #property_dictionary['File Created'] = DateTime(int(date)*1000)

        #property_dictionary['Date Created'] = DateTime(int(date)*1000)
        #property_dictionary['Date Accessed'] = DateTime(int(date)*1000)
        #property_dictionary['Date Modified'] = DateTime(int(date)*1000)


        #property_dictionary['File Modified'] = DateTime(int(date)*1000)
        #property_dictionary['Source MAC'] = s_mac
        #property_dictionary['Destination MAC'] = d_mac
        #property_dictionary['Source IP'] = s_ip
        #property_dictionary['Destination IP'] = d_ip
        #communication['Source MAC'] = s_mac
        #communication['Source IP'] = s_ip
        #communication['Destination MAC'] = d_mac
        #communication['Destination IP'] = d_ip
        #property_dictionary['Communication'] = communication
        #not working 
        #worker_item.addCustomMetadata('Source MAC', s_mac, 'string', 'user')
        #property_dictionary['Item Date'] = date
        comm = SimpleCommunication(DateTime(int(date)*1000), [SimpleAddress('', s_ip)], [SimpleAddress('', d_ip)], [], [])
        worker_item.setItemCommunication(comm)

        worker_item.setItemProperties(property_dictionary)
    except Exception as e:
        logging.critical('%s\n' % (e))
    return

def nuixWorkerItemCallbackClose():
    return
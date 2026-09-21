'''
    __G__ = "(G)bd249ce4"
    box -> sniffer
'''

from scapy.all import Ether, conf, get_if_hwaddr, sniff
from sys import stdout
from binascii import hexlify
from netifaces import ifaddresses, AF_INET, AF_LINK
from multiprocessing import Process
from datetime import datetime
from json import JSONEncoder, dumps as jdumps, loads as jloads


class ComplexEncoder(JSONEncoder):
    '''
    this will be used to encode objects
    '''

    def default(self, obj):
        '''
        override default
        '''
        if not isinstance(obj, str):
            return str(obj)
        return JSONEncoder.default(self, obj)


class QSniffer():
    def __init__(self, parsed=None, filter=None, interface=None, analyzer_db=None):
        self.current_ip = ifaddresses(interface)[AF_INET][0]['addr'].encode('utf-8')
        self.current_mac = ifaddresses(interface)[AF_LINK][0]['addr'].encode('utf-8')
        self.filter = filter
        self.interface = interface
        self.method = "ALL"
        self.task = parsed['task']
        self.logs = analyzer_db.table('sniffer_table')

    def get_layers(self, packet):
        try:
            yield packet.name
            while packet.payload:
                packet = packet.payload
                yield packet.name
        except BaseException:
            pass

    def scapy_sniffer_main(self):
        _q_s = self

        def capture_logic(packet):
            hex_payloads, _fields = {}, {}
            _layers = list(self.get_layers(packet))

            try:
                if _q_s.method == "ALL":
                    # only incoming packets - hmmmm
                    received = False
                    if packet.haslayer(Ether) and packet[Ether].dst == get_if_hwaddr(conf.iface).lower():
                        if packet[Ether].src != get_if_hwaddr(conf.iface).lower():
                            for layer in _layers:
                                try:
                                    _fields[layer] = packet[layer].fields
                                    if "load" in _fields[layer]:
                                        hex_payloads[layer] = hexlify(_fields[layer]["load"])
                                        received = True
                                except Exception as e:
                                    pass
                            dumped = jdumps({'type': 'received', 'time': datetime.now().isoformat(), 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'layers': _layers, 'fields': _fields, "payload": hex_payloads}, cls=ComplexEncoder)
                            _q_s.logs.insert(jloads(dumped))
                    if not received and packet.haslayer(Ether) and packet[Ether].src == get_if_hwaddr(conf.iface).lower():
                        for layer in _layers:
                            try:
                                _fields[layer] = packet[layer].fields
                                if "load" in _fields[layer]:
                                    hex_payloads[layer] = hexlify(_fields[layer]["load"])
                            except Exception as e:
                                pass
                        dumped = jdumps({'type': 'sent', 'time': datetime.now().isoformat(), 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'layers': _layers, 'fields': _fields, "payload": hex_payloads}, cls=ComplexEncoder)
                        _q_s.logs.insert(jloads(dumped))
            except BaseException:
                pass

            stdout.flush()

        sniff(filter=self.filter, iface=self.interface, prn=capture_logic)

    def run_sniffer(self, process=False):
        if process:
            self.sniffer = Process(name='QBSniffer', target=self.scapy_sniffer_main)
            self.sniffer.start()
        else:
            self.scapy_sniffer_main()

    def kill_sniffer(self, process=False):
        if process:
            self.sniffer.terminate()
            self.sniffer.join()

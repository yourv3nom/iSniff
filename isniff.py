# I AM VERY NEW TO PROGRAMMING, PLEASE DONT HATE, JUST INFORM ME WHAT I CAN DO BETTER <3
# this script was created by @yourv3nom on instagram to sniff your interface traffic
# This is the second version of the script so heres some notes on new shit 
# v1.0 Sniff UDP, TCP, and DNS on your local interfaces.
# v2.0 ARP, IPv6, and ICMP packet sniffing was added to sniffer along with a better and more clean feel.
import time
import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
from colorama import *

V1 = Style.BRIGHT + Fore.RED + " _____   _____       _  __  __ " + Style.RESET_ALL
V2 = Style.BRIGHT + Fore.YELLOW + "|_   _| /  ___|     (_)/ _|/ _|" + Style.RESET_ALL
V3 = Style.BRIGHT + Fore.GREEN + "  | |   \ `--. _ __  _| |_| |_ " + Style.RESET_ALL
V4 = Style.BRIGHT + Fore.BLUE + "  | |    `--. \ '_ \| |  _|  _|" + Style.RESET_ALL
V5 = Style.BRIGHT + Fore.MAGENTA + " _| |_  /\__/ / | | | | | | |  " + Style.RESET_ALL
V6 = Style.BRIGHT + Fore.CYAN + " \___/  \____/|_| |_|_|_| |_| \n " + Style.RESET_ALL
V7 = Style.BRIGHT + Fore.RED + "     Interface Sniffer v2.0" + Style.RESET_ALL
V8 = Style.BRIGHT + Fore.RED + "Created by @yourv3nom on instagram\n" + Style.RESET_ALL
V9 = Style.BRIGHT + Fore.CYAN + "Source IP: " + Style.RESET_ALL
VA = Style.BRIGHT + Fore.CYAN + " Destination IP: " + Style.RESET_ALL
VB = Style.BRIGHT + Fore.CYAN + " Destination Port: " + Style.RESET_ALL
VC = Style.BRIGHT + Fore.CYAN + " Protocol: " + Style.RESET_ALL
VD = Style.BRIGHT + Fore.CYAN + " Protocol: " + Style.RESET_ALL
VE = Style.BRIGHT + Fore.GREEN + "UDP: " + Style.RESET_ALL
VF = Style.BRIGHT + Fore.RED + "TCP: " + Style.RESET_ALL
VG = Style.BRIGHT + Fore.CYAN + """
1.) Sniff Everything
2.) Sniff UDP Packets
3.) Sniff TCP Packets
4.) Sniff DNS Queries
5.) Sniff ARP Packets
6.) Sniff ICMP Packets
7.) Sniff IPv6 Packets""" + Style.RESET_ALL
VH = Style.BRIGHT + Fore.MAGENTA + " TCP" + Style.RESET_ALL
VI = Style.BRIGHT + Fore.MAGENTA + " TCP" + Style.RESET_ALL
VJ = Style.BRIGHT + Fore.MAGENTA + " TCP" + Style.RESET_ALL
VK = Style.BRIGHT + Fore.CYAN + "UDP Packets Captured: " + Style.RESET_ALL
VL = Style.BRIGHT + Fore.CYAN + " TCP Packets Captured: " + Style.RESET_ALL
VM = Style.BRIGHT + Fore.CYAN + " DNS Packets Captured: " + Style.RESET_ALL
VN = Style.BRIGHT + Fore.CYAN + " Total Packets Captured: " + Style.RESET_ALL
VO = Style.BRIGHT + Fore.CYAN + "DNS: " + Style.RESET_ALL
VP = Style.BRIGHT + Fore.CYAN + " --> " + Style.RESET_ALL
p1 = Style.BRIGHT + Fore.BLUE + "ARP: " + Style.RESET_ALL
p2 = Style.BRIGHT + Fore.CYAN + "Total Packets: " + Style.RESET_ALL
p3 = Style.BRIGHT + Fore.CYAN + "ICMP Request: " + Style.RESET_ALL
p4 = Style.BRIGHT + Fore.CYAN + "ICMP Reply: " + Style.RESET_ALL
p5 = Style.BRIGHT + Fore.CYAN + " ICMP Packets Captured: " + Style.RESET_ALL
p6 = Style.BRIGHT + Fore.CYAN + " ARP Packets Captured: " + Style.RESET_ALL
p7 = Style.BRIGHT + Fore.CYAN + ":" + Style.RESET_ALL
p8 = Style.BRIGHT + Fore.YELLOW + "IPv6: " + Style.RESET_ALL
p9 = Style.BRIGHT + Fore.CYAN + " IPv6 Packets Captured: " + Style.RESET_ALL


def shell(cmd):
  subprocess.call(cmd, shell=True)

def start():
  shell("clear")
  print V1
  time.sleep(0.3)
  print V2
  time.sleep(0.3)
  print V3
  time.sleep(0.3)
  print V4
  time.sleep(0.3)
  print V5
  time.sleep(0.3)
  print V6
  time.sleep(0.3)                           
  print V7
  time.sleep(0.5)
  print V8
  print VG


    

pip = raw_input("Do you have pip & colorama installed? --> ")

if "Yes" in pip or "yes" in pip or "y" in pip or "Y" in pip:
  start()
if "No" in pip or "no" in pip or "n" in pip or "N" in pip:
  os = raw_input("What OS? Centos or Debian? --> ")
  if "debian" in os or "Debian" in os:
    shell("sudo apt install python-pip")
    shell("sudo pip install colorama")
    start()
  if "centos" in os or "Centos" in os or "CentOS" in os or "centOS" in os:
    shell('yum install python-pip -y')
    shell("pip install colorama")
    start()
 


sniff1 = raw_input("\nWhat option would you like to choose? --> ")
yolo = raw_input("What interface are we going to use? --> ")

t_pkt_count = 0
udp_pkt_count = 0
dns_pkt_count = 0
arp_pkt_count = 0
icmp_pkt_count = 0
ipv6_pkt_count = 0

if "1" in sniff1:
  def pktsniff(pkt):
    global t_pkt_count
    global udp_pkt_count
    global dns_pkt_count
    global icmp_pkt_count
    global arp_pkt_count
    global ipv6_pkt_count
    if pkt.haslayer('UDP'): 
      udp = pkt[UDP]
      print VE + pkt.payload.src + p7 + str(udp.sport) + VP + pkt.payload.dst + p7 +str(udp.dport) 
      udp_pkt_count += 1
    if pkt.haslayer('TCP'):
      tcp = pkt[TCP]
      print VF + pkt.payload.src + p7 + str(tcp.sport) + VP+ pkt.payload.dst + p7 + str(tcp.dport) 
      t_pkt_count += 1
    if IP in pkt:
          ip_src = pkt[IP].src
          ip_dst = pkt[IP].dst
          if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                  print VO + str(ip_dst) + VP + "(" + pkt.getlayer(DNS).qd.qname + ")" 
                  dns_pkt_count +=1 
    if pkt.haslayer("ARP"):
      print p1 + pkt.src + VP + pkt.dst + VP + str(pkt.payload.ptype)
      arp_pkt_count += 1
    if pkt.haslayer("ICMP"):
      if "8" in str(pkt.getlayer(ICMP).type):
        print p3 + pkt[IP].src + VP + pkt[IP].dst
        print p4 + pkt[IP].dst + VP + pkt[IP].src
        icmp_pkt_count += 2
    if pkt.haslayer("IPv6"):
      if pkt.haslayer("UDP"):
     	 print p8 + pkt.payload.src + p7 + str(pkt[UDP].sport) + VP + pkt.payload.dst + p7 + str(pkt[UDP].dport)
	 ipv6_pkt_count += 1
      print p8 + pkt.payload.src + VP + pkt.payload.dst
      ipv6_pkt_count += 1 
if "2" in sniff1:
  def pktsniff(pkt):
    global udp_pkt_count
    if pkt.haslayer('UDP'): 
      udp = pkt[UDP]
      print VE + pkt.payload.src + p7 + str(udp.sport) + VP + pkt.payload.dst + p7 +str(udp.dport) 
      udp_pkt_count += 1
if "3" in sniff1: 
  def pktsniff(pkt):
    global t_pkt_count
    if pkt.haslayer('TCP'): 
      tcp = pkt[TCP]
      print VF + pkt.payload.src + VA + pkt.payload.dst + VB + str(tcp.dport) 
      t_pkt_count += 1
if "4" in sniff1:
  def pktsniff(pkt):
    global dns_pkt_count
    if IP in pkt:
          ip_src = pkt[IP].src
          ip_dst = pkt[IP].dst
          if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                  print VO + str(ip_dst) + VP + "(" + pkt.getlayer(DNS).qd.qname + ")" 
                  dns_pkt_count +=1 
if "5" in sniff1:
  def pktsniff(pkt):
    global arp_pkt_count
    if pkt.haslayer("ARP"):
      print p1 + pkt.src + VP + pkt.dst + VP + str(pkt.payload.ptype)
      arp_pkt_count += 1
if "6" in sniff1:
  def pktsniff(pkt):
    if pkt.haslayer("ICMP"):
      if "8" in str(pkt.getlayer(ICMP).type):
        print p3 + pkt[IP].src + VP + pkt[IP].dst
        print p4 + pkt[IP].dst + VP + pkt[IP].src
        icmp_pkt_count += 2
if "7" in sniff1:
  def pktsniff(pkt):
    global ipv6_pkt_count
    if pkt.haslayer("IPv6"):
      print p8 + pkt.payload.src + p7 + str(pkt[UDP].sport) + VP + pkt.payload.dst + p7 + str(pkt[UDP].dport)
      ipv6_pkt_count += 1
def main():
  if "1" in sniff1: 
    sniff(iface = yolo,prn=pktsniff)
    print "\n" + VK + "[" + str(udp_pkt_count) + "]" + VL + "[" + str(t_pkt_count) + "]" + VM + "[" + str(dns_pkt_count) + "]" + p5 + "[" + str(icmp_pkt_count) + "]" + p6 + "[" + str(arp_pkt_count) + "]" + p9 + "[" + str(ipv6_pkt_count) + "]" + VN + "[" + str(udp_pkt_count + t_pkt_count + dns_pkt_count + icmp_pkt_count + arp_pkt_count) + "]"
  if "2" in sniff1:
    sniff(iface = yolo,prn=pktsniff)
    print "\n" + VK + "[" +  str(udp_pkt_count) + "]"
  if "3" in sniff1:
    sniff(iface = yolo,prn=pktsniff)
    print "\n" + VL + "[" + str(t_pkt_count) + "]"
  if "4" in sniff1:
    sniff(iface = yolo,filter = "port 53", prn = pktsniff, store = 0)
    print "\n" + VM + "[" + str(dns_pkt_count) + "]"
  if "5" in sniff1:
    sniff(iface = yolo, prn=pktsniff, store = 0) 
    print "\n" + p6 + "[" + str(arp_pkt_count) + "]" 
  if "6" in sniff1:
	  sniff(iface = yolo, prn=pktsniff)
	  print "\n" +  p5 + "[" + str(icmp_pkt_count) + "]"
  if "7" in sniff1:
	  sniff(iface = yolo, prn=pktsniff)
	  print "\n" + p9 + "[" + str(ipv6_pkt_count) + "]" 
     
        
  print "\n"
  print "\n"
  print "Goodbye :)\n"
  print "\n"
    
if __name__ == '__main__':
      main()

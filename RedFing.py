import socket
import ipaddress
import pyfiglet
import os
import nmap

tool = pyfiglet.figlet_format('Red Prey')

red = '\033[91m'
reset = '\033[0m'

clear_inf = 0

while clear_inf < 7:
        clear = os.system('clear')
        clear_inf += 1

# nmap
def scan_networki(networki_cidr):
        try:
                nm = nmap.PortScanner()
        except Exception as e:
                print(f'{red}Erro ao usar criar portscanner erro: {e}{reset} ')
                print(f'confira se nmap esta intalado junto com o python-nmap')
                

# PULL IP

def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip

my_ip = get_local_ip()

network = ipaddress.ip_network(my_ip + '/24', strict=False)
#interface

print (red + tool + reset)
print (red + '_' * 40 + reset)
print (red + '\n[1] Scan\n[2] IP' + reset)

choice_tool = input(red + '\nchoice the tool: ' + reset).lower()

match choice_tool:
        case '1' | 'scan':
                print (red + '\n[1] Scan on IP(full networking)')
                print ('[2] Scan open door: ' + reset)
                
                choice_type_scan = input(red + '\nchoose the scan type: ' + reset).lower()
                
                if choice_type_scan in ('1', 'scan on ip', 'full networking'):
                        print (red + '_' * 60)
                        print ('Scan in progress')
                        #nm.scan(hosts=network, arguments='-sP')
                        #full_scan = os.system(f'nmap {network} -sP')
                        print ('_' * 60)
                elif choice_type_scan in ('2', 'scan open door'):
                        pass
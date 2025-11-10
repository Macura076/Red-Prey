import socket
import ipaddress
import pyfiglet
import os
import nmap
import sys
import time

tool = pyfiglet.figlet_format('Red Prey')

red = '\033[91m'
reset = '\033[0m'

clear_inf = 0
while clear_inf < 7:
    os.system('cls')
    clear_inf += 1

def scan_networki(networki_cidr):
    try:
        nm = nmap.PortScanner()
    except Exception as e:
        print(f"{red}Erro ao criar PortScanner: {e}{reset}")
        print(f"{red}Verifique se o 'nmap' está instalado no sistema e 'python-nmap' no Python.{reset}")
        return []

    print(f"{red}Iniciando ping-scan em {networki_cidr}...{reset}")
    try:
        nm.scan(hosts=networki_cidr, arguments='-sn')  
    except Exception as e:
        print(f"{red}Erro ao executar nmap: {e}{reset}")
        return []

    hosts = []
    for host in nm.all_hosts():
        try:
            status = nm[host].get('status', {}).get('state', 'unknown')
            addresses = nm[host].get('addresses', {})
            ip = addresses.get('ipv4', addresses.get('ipv6', ''))
            mac = addresses.get('mac', '')
            hostname = nm[host].hostname() or ''
            hosts.append({
                'ip': ip,
                'status': status,
                'hostname': hostname,
                'mac': mac
            })
        except Exception:
            continue

    return hosts

def scan_ports(target_ip, port_range='1-1024'):
    try:
        nm = nmap.PortScanner()
    except Exception as e:
        print(f"{red}Erro ao criar PortScanner: {e}{reset}")
        return []

    print(f"{red}Iniciando scan de portas em {target_ip} (portas {port_range})...{reset}")
    try:
        nm.scan(hosts=target_ip, arguments=f'-p {port_range} --open')
    except Exception as e:
        print(f"{red}Erro ao executar nmap: {e}{reset}")
        return []

    results = []
    if target_ip in nm.all_hosts():
        try:
            proto = 'tcp'
            ports = nm[target_ip].get('tcp', {}) if proto == 'tcp' else nm[target_ip].get('udp', {})
            for portnum, info in ports.items():
                state = info.get('state', '')
                name = info.get('name', '')
                product = info.get('product', '')
                results.append({
                    'port': portnum,
                    'state': state,
                    'service': f"{name} {product}".strip()
                })
        except Exception:
            for proto in nm[target_ip].keys():
                if isinstance(nm[target_ip][proto], dict):
                    for portnum, info in nm[target_ip][proto].items():
                        results.append({
                            'port': portnum,
                            'state': info.get('state', ''),
                            'service': info.get('name', '')
                        })
    return results

def get_local_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"{red}Não foi possível detectar IP local automaticamente: {e}{reset}")
        return None
    finally:
        if s:
            s.close()

def main():
    my_ip = get_local_ip()
    if not my_ip:
        my_ip = input("Digite o IP da sua interface (ex: 192.168.1.10): ").strip()

    try:
        network = ipaddress.ip_network(my_ip + '/24', strict=False)
    except Exception as e:
        print(f"{red}IP inválido: {e}{reset}")
        sys.exit(1)

    print(red + tool + reset)
    print(red + '_' * 40 + reset)
    print(red + '\n[1] Scan\n[2] IP' + reset)

    choice_tool = input(red + '\nchoice the tool: ' + reset).lower()

    match choice_tool:
        case '1' | 'scan':
            print(red + '\n[1] Scan on IP (full networking)')
            print('[2] Scan open door (scan de portas) ' + reset)

            choice_type_scan = input(red + '\nchoose the scan type: ' + reset).lower()

            if choice_type_scan in ('1', 'scan on ip', 'full networking'):
                print(red + '_' * 60 + reset)
                print(red + 'Scan in progress (ping scan)...' + reset)
                hosts = scan_networki(str(network.with_prefixlen))
                print(red + '_' * 60 + reset)
                if not hosts:
                    print(f"{red}Nenhum host ativo encontrado ou erro no scan.{reset}")
                else:
                    print(f"{red}Hosts ativos encontrados:")
                    print('')
                    for h in hosts:
                        print(f"- {h['ip']}  status={h['status']} hostname='{h['hostname']}' mac='{h['mac']}'")
                print('_' * 60 + reset)
            elif choice_type_scan in ('2', 'scan open door', 'scan portas'):
                print(red + '_' * 41 + reset)
                choice_target = input(red + '\nqual alvo seu alvo: ' + reset)
                choice_dorrs = input(red + 'escolha a quantidade de portas: ' + reset)
                print('')
                print(red + '_' * 41 + reset)
                print(red + '\nScan in progress...')
                print('')
                os.system(f'nmap -D RND:20 --top-ports={choice_dorrs} {choice_target}')
                print('_' * 41 + reset)
            else:
                print(red + "Opção de scan inválida." + reset)
        case '2' | 'ip':
            print(f"{red}IP detectado: {my_ip}{reset}")
        case _:
            print(red + "Opção inválida. Saindo." + reset)

if __name__ == "__main__":
    main()

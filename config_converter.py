import sys
import json
import base64
import socket
from urllib.parse import urlparse, parse_qs, unquote, urlunparse, urlencode

def parse_vless(link):
    """Parses a vless:// link and returns ONLY the outbound object."""
    parsed_url = urlparse(link)
    params = parse_qs(parsed_url.query)
    
    address = parsed_url.hostname
    
    outbound = {
        "tag": unquote(parsed_url.fragment) if parsed_url.fragment else f"vless-{address}",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address,
                "port": parsed_url.port,
                "users": [{
                    "id": parsed_url.username,
                    "encryption": params.get('encryption', ['none'])[0],
                    "flow": params.get('flow', [''])[0]
                }]
            }]
        },
        "streamSettings": {
            "network": params.get('type', ['tcp'])[0],
            "security": params.get('security', ['none'])[0]
        }
    }
    
    security_type = params.get('security', ['none'])[0]
    
    if security_type == 'tls':
        sni_value = params.get('sni', [None])[0]
        host_value = params.get('host', [None])[0]
        authority_value = params.get('authority', [None])[0]
        server_name = sni_value if sni_value else authority_value if authority_value else host_value if host_value else address
        tls_settings = {"serverName": server_name, "alpn": params.get('alpn', ["h2", "http/1.1"])}
        if 'fp' in params: tls_settings['fingerprint'] = params['fp'][0]
        outbound['streamSettings']['tlsSettings'] = tls_settings

    elif security_type == 'reality':
        sni_value = params.get('sni', [None])[0]
        host_value = params.get('host', [None])[0]
        server_name = sni_value if sni_value else host_value if host_value else address
        reality_settings = {
            "serverName": server_name,
            "fingerprint": params.get('fp', ['chrome'])[0],
            "publicKey": params.get('pbk', [''])[0],
            "shortId": params.get('sid', [''])[0],
            "spiderX": params.get('spx', ['/'])[0]
        }
        outbound['streamSettings']['realitySettings'] = reality_settings

    network_type = params.get('type', ['tcp'])[0]

    if network_type == 'ws':
        host = params.get('host', [address])[0]
        outbound['streamSettings']['wsSettings'] = {
            "path": params.get('path', ['/'])[0],
            "headers": {"Host": host} if host else {}
        }
    elif network_type == 'httpupgrade':
        host = params.get('host', [address])[0]
        outbound['streamSettings']['httpUpgradeSettings'] = {
            "path": params.get('path', ['/'])[0],
            "host": host
        }
    elif network_type == 'xhttp':
        host = params.get('host', [address])[0]
        xhttp_settings = {
            "path": params.get('path', ['/'])[0],
            "host": host,
            "mode": params.get('mode', ['auto'])[0]
        }
        if 'extra' in params:
            try:
                extra_params = json.loads(params['extra'][0])
                xhttp_settings.update(extra_params)
            except json.JSONDecodeError:
                pass
        outbound['streamSettings']['xhttpSettings'] = xhttp_settings
    elif network_type == 'grpc':
        grpc_settings = {
            "serviceName": params.get('serviceName', [''])[0],
            "multiMode": params.get('mode', ['gun'])[0] == 'multi'
        }
        if 'authority' in params and params['authority'][0]:
            grpc_settings['authority'] = params['authority'][0]
        outbound['streamSettings']['grpcSettings'] = grpc_settings
    elif network_type == 'tcp':
        header_type = params.get('headerType', ['none'])[0]
        if header_type != 'none':
            outbound['streamSettings']['tcpSettings'] = {
                "header": {"type": header_type}
            }
        
    return outbound

def parse_ss(link):
    """Parses a ss:// link and returns ONLY the outbound object."""
    parsed_url = urlparse(link)
    
    tag = unquote(parsed_url.fragment) if parsed_url.fragment else f"ss-{parsed_url.hostname}"
    
    try:
        decoded_userinfo = base64.b64decode(parsed_url.username + '==').decode('utf-8')
        method, password = decoded_userinfo.split(':', 1)
    except Exception:
        return None

    outbound = {
        "tag": tag,
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": parsed_url.hostname,
                    "port": parsed_url.port,
                    "password": password,
                    "method": method
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "none"
        }
    }
    return outbound

def parse_vmess(link):
    """Parses a vmess:// link and returns ONLY the outbound object."""
    if not link.startswith("vmess://"):
        return None
    
    try:
        decoded_part = base64.b64decode(link[8:] + '==').decode('utf-8')
        vmess_data = json.loads(decoded_part)
    except Exception:
        return None

    address = vmess_data.get('add', '')
    
    outbound = {
        "tag": unquote(vmess_data.get('ps', f"vmess-{address}")),
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": int(vmess_data.get('port', 443)),
                    "users": [
                        {
                            "id": vmess_data.get('id'),
                            "alterId": int(vmess_data.get('aid', 0)),
                            "security": vmess_data.get('scy', 'auto')
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": vmess_data.get('net', 'tcp'),
            "security": vmess_data.get('tls', 'none')
        }
    }

    network_type = vmess_data.get('net', 'tcp')
    
    if vmess_data.get('tls') == 'tls':
        sni = vmess_data.get('sni', vmess_data.get('host', ''))
        tls_settings = {"serverName": sni}
        if vmess_data.get('alpn'):
            tls_settings['alpn'] = vmess_data['alpn'].split(',')
        if vmess_data.get('fp'):
            tls_settings['fingerprint'] = vmess_data['fp']
        outbound['streamSettings']['tlsSettings'] = tls_settings

    if network_type == 'tcp':
        header_type = vmess_data.get('type', 'none')
        if header_type != 'none':
             outbound['streamSettings']['tcpSettings'] = {
                "header": {"type": header_type}
            }
    elif network_type == 'ws':
        ws_settings = {
            "path": vmess_data.get('path', '/'),
            "headers": {}
        }
        if vmess_data.get('host'):
            ws_settings['headers']['Host'] = vmess_data['host']
        outbound['streamSettings']['wsSettings'] = ws_settings
    elif network_type == 'xhttp':
        xhttp_settings = {
            "path": vmess_data.get('path', '/'),
            "host": vmess_data.get('host', ''),
            "mode": vmess_data.get('mode', 'auto')
        }
        outbound['streamSettings']['xhttpSettings'] = xhttp_settings
    elif network_type == 'httpupgrade':
        httpupgrade_settings = {
            "path": vmess_data.get('path', '/'),
            "host": vmess_data.get('host', '')
        }
        outbound['streamSettings']['httpupgradeSettings'] = httpupgrade_settings
    elif network_type == 'grpc':
        grpc_settings = {
            "serviceName": vmess_data.get('path', ''),
            "authority": vmess_data.get('authority', ''),
            "multiMode": vmess_data.get('mode', 'gun') == 'multi'
        }
        outbound['streamSettings']['grpcSettings'] = grpc_settings
    elif network_type == 'kcp':
        kcp_settings = {
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 5,
            "downlinkCapacity": 20,
            "congestion": False,
            "readBufferSize": 2,
            "writeBufferSize": 2,
            "header": {"type": vmess_data.get('type', 'none')},
            "seed": vmess_data.get('path', '')
        }
        outbound['streamSettings']['kcpSettings'] = kcp_settings
    
    return outbound

def parse_trojan(link):
    """Parses a trojan:// link and returns ONLY the outbound object."""
    parsed_url = urlparse(link)
    params = parse_qs(parsed_url.query)
    
    address = parsed_url.hostname
    
    outbound = {
        "tag": unquote(parsed_url.fragment) if parsed_url.fragment else f"trojan-{address}",
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": address,
                "port": parsed_url.port,
                "password": parsed_url.username
            }]
        },
        "streamSettings": {
            "network": params.get('type', ['tcp'])[0],
            "security": params.get('security', ['none'])[0]
        }
    }
    
    security_type = params.get('security', ['none'])[0]

    if security_type == 'tls':
        sni = params.get('sni', [params.get('host', [address])[0]])[0]
        tls_settings = {"serverName": sni, "alpn": params.get('alpn', ["h2", "http/1.1"])}
        if 'fp' in params: tls_settings['fingerprint'] = params['fp'][0]
        outbound['streamSettings']['tlsSettings'] = tls_settings
    
    elif security_type == 'reality':
        sni = params.get('sni', [params.get('host', [address])[0]])[0]
        reality_settings = {
            "serverName": sni,
            "fingerprint": params.get('fp', ['chrome'])[0],
            "publicKey": params.get('pbk', [''])[0],
            "shortId": params.get('sid', [''])[0],
            "spiderX": params.get('spx', ['/'])[0]
        }
        outbound['streamSettings']['realitySettings'] = reality_settings

    if params.get('type') == ['tcp']:
        header_type = params.get('headerType', ['none'])[0]
        if header_type != 'none':
             outbound['streamSettings']['tcpSettings'] = {
                "header": {"type": header_type}
            }
            
    return outbound

def to_outbound_dispatch(link):
    """Dispatches to the correct parser based on the link scheme."""
    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    else:
        return None

def to_link(outbound_obj):
    """Converts an outbound object back to a V2Ray link."""
    # This function is complex to implement for all types.
    # For now, it's a placeholder for future development.
    return None

def generate_test_config(link, port):
    """Generates a full config for testing a single link."""
    outbound = to_outbound_dispatch(link)
    if not outbound: return None

    try:
        if outbound['protocol'] in ['shadowsocks', 'trojan']:
            address_to_resolve = outbound['settings']['servers'][0]['address']
            ip_address = socket.gethostbyname(address_to_resolve)
            outbound['settings']['servers'][0]['address'] = ip_address
        else: # For vless/vmess
            address_to_resolve = outbound['settings']['vnext'][0]['address']
            ip_address = socket.gethostbyname(address_to_resolve)
            outbound['settings']['vnext'][0]['address'] = ip_address
    except socket.gaierror:
        pass

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks", "port": int(port), "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [outbound],
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"]}
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "to-outbound" and len(sys.argv) > 2:
        link = sys.argv[2]
        outbound_obj = to_outbound_dispatch(link)
        if outbound_obj: print(json.dumps(outbound_obj, indent=2))
    
    elif command == "to-link" and len(sys.argv) > 2:
        obj_str = sys.argv[2]
        obj = json.loads(obj_str)
        link = to_link(obj)
        if link: print(link)

    elif command == "test-config" and len(sys.argv) > 3:
        link = sys.argv[2]
        port = sys.argv[3]
        config = generate_test_config(link, port)
        if config: print(json.dumps(config, indent=2))
        
    else:
        sys.exit(1)

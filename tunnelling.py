import subprocess
import os
import time
import tempfile
import python_wireguard
import requests

def create_temp_config_file(peer_public_key, peer_endpoint):
    private_key, public_key = python_wireguard.Key.key_pair()
    own_public_ip = requests.get("https://ifconfig.me").text.strip()

    print(own_public_ip)

    config_template = f"""[Interface]
    PrivateKey = {private_key}
    Address = {own_public_ip}/24
    DNS = 8.8.8.8
    ListenPort = 33333

    [Peer]
    PublicKey = {peer_public_key}
    AllowedIPs = 0.0.0.0/0, ::/0
    Endpoint = {peer_endpoint}
    """

    #since we dont have a predetermined list of ip addresses that we will be communicating with, i need to include all addresses in the allowed ips

    fd, path = tempfile.mkstemp(suffix='.conf')

    try:
        with os.fdopen(fd, 'w') as tmp:    #convert an fd to a python file object and open it for write
            tmp.write(config_template)
            print(path)
    except:
        os.remove(path)  #dispose in case of an error
        raise
    
    return path

def set_up_interface(config_path, interface_name="wg0"):
    try:
        subprocess.run(['wg-quick', 'up', config_path], check=True)
        print("interface has been brought up!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"failed to bring up interface: {e}")
        return False


def stop_interface(config_path):
    try:
        subprocess.run(['wg-quick', 'down', config_path], check=True)
        print("interface has been brought down!")
    except subprocess.CalledProcessError as e:
        print(f"failed to bring down interface: {e}")
    finally:
        try:
            os.remove(config_path)
        except OSError:
            pass

config_path = create_temp_config_file("4I85ikHFpEV+fzxhATL8k5RS0imIS0LYeulKMs/qLXI=", "100.20.100.0/33333")
set_up_interface(config_path)
stop_interface(config_path)
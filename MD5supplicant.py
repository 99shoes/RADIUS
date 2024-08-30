import hmac
import hashlib
from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
import logging

logging.basicConfig(level=logging.DEBUG)

def eapol_start(authenticator_mac):
    frame = Ether(dst=authenticator_mac) / EAPOL(version=3, type=1)
    logging.debug(f"EAPOL-Start Frame:\n {frame.show(dump=True)}")
    return frame

def eap_response_identity(id, supplicant_mac, authenticator_mac, username):
    frame = Ether(dst=authenticator_mac, src=supplicant_mac) / EAPOL(version=3, type=0) / EAP(code=2, id=id, type=1) / username
    logging.debug(f"EAP-Response/Identity Frame:\n {frame.show(dump=True)}")
    return frame

def eap_response_md5(id, supplicant_mac, authenticator_mac, password, eap_md5_challenge):
    eap_md5_value = hashlib.md5(bytes([id]) + password.encode() + eap_md5_challenge).digest()
    eap_md5_length = len(eap_md5_value)
    frame = Ether(dst=authenticator_mac, src=supplicant_mac) / EAPOL(version=3, type=0) / EAP(code=2, id=id, type=4, len=5 + eap_md5_length) / (eap_md5_length).to_bytes(1, byteorder='big') / eap_md5_value
    logging.debug(f"EAP-Response/MD5 Frame:\n {frame.show(dump=True)}")
    return frame

def handle_supplicant(iface, authenticator_mac, username, password):
    supplicant_mac = get_if_hwaddr(iface)
    
    sendp(eapol_start(authenticator_mac), iface=iface)
    logging.debug(f"Sent EAPOL-Start to {authenticator_mac}")

    response = sniff(iface=iface, count=5, timeout=60, filter="ether proto 0x888e")
    if response and EAP in response[0] and response[0][EAP].code == 1 and response[0][EAP].type == 1:
        logging.debug("Supplicant: Received EAP-Request/Identity from Authenticator")
        id = response[0][EAP].id
        sendp(eap_response_identity(id, supplicant_mac, authenticator_mac, username), iface=iface)
        logging.debug(f"Sent EAP-Response/Identity to {authenticator_mac}")
        
        response = sniff(iface=iface, count=5, timeout=60, filter="ether proto 0x888e")
        if response and EAP in response[0] and response[0][EAP].code == 1 and response[0][EAP].type == 4:
            logging.debug("Supplicant: Received EAP-Request/MD5-Challenge from Authenticator")
            id = response[0][EAP].id
            eap_md5_challenge = response[0][EAP].payload.load[1:]
            sendp(eap_response_md5(id, supplicant_mac, authenticator_mac, password, eap_md5_challenge), iface=iface)
            
            response = sniff(iface=iface, count=5, timeout=60, filter="ether proto 0x888e")
            if response and EAP in response[0] and response[0][EAP].code == 3:
                logging.debug("Supplicant: Authentication successful, received EAP-Success")
            elif response and EAP in response[0] and response[0][EAP].code == 4:
                logging.debug("Supplicant: Authentication failed, received EAP-Failure")
            else:
                logging.error("Supplicant: Did not receive EAP-Success or EAP-Failure")
        else:
            logging.error("Supplicant: Did not receive EAP-Request/MD5-Challenge from Authenticator")
    else:
        logging.error("Supplicant: Did not receive EAP-Request/Identity from Authenticator")

if __name__ == "__main__":
    iface = "ens160"  # Interface on the Supplicant
    authenticator_mac = "00:50:56:a4:1d:a4"  # Authenticator MAC address
    username = "ludy"  # Username to use for authentication
    password = "password"  # Password to use for MD5 authentication
    handle_supplicant(iface, authenticator_mac, username, password)

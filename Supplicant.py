import logging
import hashlib
from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.l2 import Ether

logging.basicConfig(level=logging.DEBUG)

def eapol_start():
    """Create and send an EAPOL-Start packet to initiate the authentication process."""
    frame = Ether() / EAPOL(version=3, type=1)  # EAPOL-Start
    logging.debug(f"EAPOL-Start Frame:\n {frame.show(dump=True)}")
    return frame

def eap_response_identity(id, username):
    """Create an EAP-Response/Identity packet."""
    frame = Ether() / EAPOL(version=3, type=0) / EAP(code=2, id=id, type=1) / username.encode()
    logging.debug(f"EAP-Response/Identity Frame:\n {frame.show(dump=True)}")
    return frame

def eap_response_md5(id, challenge, password):
    """Create an EAP-Response/MD5-Challenge packet."""
    # Calculate MD5 hash of the challenge concatenated with the password
    md5_hash = hashlib.md5(chr(id).encode() + password.encode() + challenge).digest()
    frame = Ether() / EAPOL(version=3, type=0) / EAP(code=2, id=id, type=4) / md5_hash
    logging.debug(f"EAP-Response/MD5-Challenge Frame:\n {frame.show(dump=True)}")
    return frame

def send_eapol_start(iface):
    """Send an EAPOL-Start packet to initiate the authentication process."""
    logging.debug("Sending EAPOL-Start to Authenticator")
    packet = eapol_start()
    sendp(packet, iface=iface)

def handle_supplicant(iface, username, password):
    id = 1  # Identifier for EAP frames

    # Send EAPOL-Start to initiate the authentication process
    send_eapol_start(iface)

    logging.debug("Waiting for EAP-Request/Identity from Authenticator")
    response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
    if response:
        logging.debug(f"Received packet: {response[0].summary()}")
        if EAP in response[0] and response[0][EAP].code == 1 and response[0][EAP].type == 1:
            logging.debug("Received EAP-Request/Identity from Authenticator")
            sendp(eap_response_identity(id, username), iface=iface)

            logging.debug("Waiting for EAP-Request/MD5-Challenge from Authenticator")
            response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
            if response and EAP in response[0] and response[0][EAP].code == 1 and response[0][EAP].type == 4:
                logging.debug("Received EAP-Request/MD5-Challenge from Authenticator")
                challenge = response[0][EAP].payload.load[1:]  # Extract challenge from payload
                sendp(eap_response_md5(id, challenge, password), iface=iface)

                logging.debug("Waiting for EAP-Success/EAP-Failure from Authenticator")
                response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
                if response and EAP in response[0] and response[0][EAP].code == 3:
                    if response[0][EAP].code == 3:
                        logging.info("Authentication successful")
                    else:
                        logging.info("Authentication failed")
                else:
                    logging.error("Failed to receive EAP-Success/EAP-Failure from Authenticator")
            else:
                logging.error("Failed to receive EAP-Request/MD5-Challenge from Authenticator")
        else:
            logging.error("Failed to receive EAP-Request/Identity from Authenticator")
    else:
        logging.error("Failed to receive any packets from Authenticator")

if __name__ == "__main__":
    iface = "ens160"  # Replace with your network interface
    username = "ludy"  # Replace with your username
    password = "password"  # Replace with your EAP-MD5 password

    handle_supplicant(iface, username, password)

import hmac
import hashlib
from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept, AccessReject
import logging

logging.basicConfig(level=logging.DEBUG)

def eap_request_identity(id, client_mac):
    frame = Ether(dst=client_mac) / EAPOL(version=3, type=0) / EAP(code=1, id=id, type=1)  # version=3 for 802.1X-2020, type=0 for EAP-Packet
    logging.debug(f"EAP-Request/Identity Frame:\n {frame.show(dump=True)}")
    return frame

def eap_request_tls(id, data, client_mac):
    frame = Ether(dst=client_mac) / EAPOL(version=3, type=0) / EAP(code=1, id=id, type=13) / data
    logging.debug(f"EAP-Request/TLS Frame: {frame.show(dump=True)}")
    return frame

def eap_success(id, client_mac):
    frame = Ether(dst=client_mac) / EAPOL(version=3, type=0) / EAP(code=3, id=id)
    logging.debug(f"EAP-Success Frame: {frame.show(dump=True)}")
    return frame

def eap_failure(id, client_mac):
    frame = Ether(dst=client_mac) / EAPOL(version=3, type=0) / EAP(code=4, id=id)
    logging.debug(f"EAP-Failure Frame: {frame.show(dump=True)}")
    return frame

def calculate_message_authenticator(packet, secret):
    raw_packet = packet.RequestPacket()
    hmac_md5 = hmac.new(secret, raw_packet, hashlib.md5)
    return hmac_md5.digest()

def authenticate_with_radius_tls(tls_data, client_mac, username):
    try:
        logging.debug("Creating RADIUS client for TLS authentication")
        srv = Client(server="192.168.30.166", authport=1812, acctport=1813, secret=b"testing123", dict=Dictionary("/etc/freeradius/3.0/dictionary"))
        srv.retries = 5
        srv.timeout = 10
        req = srv.CreateAuthPacket(code=AccessRequest)

        req.AddAttribute("User-Name", username)  # Add User-Name attribute
        req.AddAttribute("NAS-Port-Type", 15)  # Example attribute
        req.AddAttribute("EAP-Message", tls_data)
        req.AddAttribute("Calling-Station-Id", client_mac)
        req.AddAttribute("Message-Authenticator", b'\x00' * 16)  # Placeholder for HMAC
        # Calculate the real Message-Authenticator
        message_authenticator = calculate_message_authenticator(req, srv.secret)
        req["Message-Authenticator"] = message_authenticator

        logging.debug(f"RADIUS Request: {req}")
        reply = srv.SendPacket(req)
        logging.debug(f"RADIUS Reply: {reply}")
        return reply.code == AccessAccept

    except Timeout:
        logging.error("A Timeout occurred during RADIUS authentication")
        raise
    except Exception as e:
        logging.error(f"An error occurred during RADIUS authentication: {e}", exc_info=True)
        raise

def handle_authenticator(iface):
    id = 1
    logging.debug("Waiting for EAPOL-Start from client")
    response = sniff(iface=iface, count=5, timeout=20, filter="ether proto 0x888e")
    if response:
        logging.debug(f"Received packet: {response[0].summary()}")
        if EAPOL in response[0] and response[0][EAPOL].type == 1:
            logging.debug("Received EAPOL-Start from client")
            client_mac = response[0].src
            sendp(eap_request_identity(id, client_mac), iface=iface)
            response = sniff(iface=iface, count=5, timeout=60, filter="ether proto 0x888e")
            print(response, 'dwd')
            print("hello")
            if response and EAP in response[0] and response[0][EAP].code == 2 and response[0][EAP].type == 1:
                logging.debug("Authenticator: Received EAP-Response/Identity from Supplicant")
                username = response[0][EAP].identity.decode()  # Extract username from EAP response
                logging.debug(f"Authenticator: Username extracted: {username}")
                sendp(eap_request_tls(id, b"TLS_Start", client_mac), iface=iface)# problem
                response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
                print("hello",response)
                if response and EAP in response[0] and response[0][EAP].code == 2 and response[0][EAP].type == 13:
                    tls_data = response[0][EAP].payload.load
                    if authenticate_with_radius_tls(tls_data, client_mac, username):
                        sendp(eap_success(id, client_mac), iface=iface)
                    else:
                        sendp(eap_failure(id, client_mac), iface=iface)
                else:
                    logging.error("Failed to receive EAP-Response/TLS from client")
            else:
                logging.error("Failed to receive EAP-Response/Identity from client")
        else:
            logging.error("Received packet is not EAPOL-Start")
    else:
        logging.error("Failed to receive EAPOL-Start from client")

if __name__ == "__main__":
    iface = "ens160"  # Interface on the Authenticator
    handle_authenticator(iface)

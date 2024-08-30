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
    logging.debug(f"EAP-Success Frame: {frame.show(dump(True))}")
    return frame

def eap_failure(id, client_mac):
    frame = Ether(dst=client_mac) / EAPOL(version=3, type=0) / EAP(code=4, id=id)
    logging.debug(f"EAP-Failure Frame: {frame.show(dump=True)}")
    return frame

def calculate_message_authenticator(packet, secret):
    raw_packet = packet.RequestPacket()
    hmac_md5 = hmac.new(secret, raw_packet, hashlib.md5)
    return hmac_md5.digest()

def authenticate_with_radius(username, password, challenge):
    try:
        logging.debug("Creating RADIUS client")
        srv = Client(server="192.168.30.166", authport=1812, acctport=1813, secret=b"testing123", dict=Dictionary("/etc/freeradius/3.0/dictionary"))
        srv.retries = 5
        srv.timeout = 10
        req = srv.CreateAuthPacket(code=AccessRequest, User_Name=username)

        logging.debug(f"Username: {username}, Password: {password}")

        req.AddAttribute("User-Name", username)
        req.AddAttribute("User-Password", password)
        req.AddAttribute("CHAP-Challenge", challenge)
        req.AddAttribute("Message-Authenticator", b'\x00' * 16)

        message_authenticator = calculate_message_authenticator(req, srv.secret)
        req["Message-Authenticator"] = message_authenticator

        logging.debug(f"RADIUS Request: {req}")

        for attr in req.keys():
            logging.debug(f"Attribute {attr}: {req[attr]}")
        reply = srv.SendPacket(req)
        logging.debug(f"RADIUS Reply: {reply}")
        if reply.code == AccessAccept:
            logging.info("Access accepted by the RADIUS server")
            return True
        elif reply.code == AccessReject:
            logging.error("Access rejected by the RADIUS server")
            return False
        else:
            logging.error(f"Received unexpected RADIUS reply code: {reply.code}")
            return False

    except Timeout:
        logging.error("A Timeout occurred during RADIUS authentication")
        raise
    except KeyError as e:
        logging.error(f"A KeyError occurred during RADIUS authentication: {e}")
        raise
    except Exception as e:
        logging.error(f"An error occurred during RADIUS authentication: {e}", exc_info=True)
        raise

def handle_authenticator(iface):
    id = 1
    logging.debug("Waiting for EAPOL-Start from client")
    response = sniff(iface=iface, count=1, timeout=20, filter="ether proto 0x888e")
    if response:
        logging.debug(f"Received packet: {response[0].summary()}")
        if EAPOL in response[0] and response[0][EAPOL].type == 1:
            logging.debug("Received EAPOL-Start from client")
            client_mac = response[0].src
            print("CL",client_mac)
            sendp(eap_request_identity(id, client_mac), iface=iface)#question
            response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
            print(response, 'dwd')
            if response:
                logging.debug(f"Received packet: {response[0].summary()}")
                if EAP in response[0] and response[0][EAP].code == 2 and response[0][EAP].type == 1:
                    if hasattr(response[0][EAP], 'identity'):
                        username = response[0][EAP].identity.decode()
                        logging.debug(f"Received EAP-Response/Identity from client: {username}")
                    else:
                        username = response[0][EAP].payload.load.decode()
                        logging.debug(f"Received EAP-Response/Identity from client: {username}")
                    challenge = b"random_challenge"
                    if authenticate_with_radius(username, "password", challenge):
                        sendp(eap_success(id, client_mac), iface=iface)
                    else:
                        sendp(eap_failure(id, client_mac), iface=iface)
                else:
                    logging.error("Failed to receive EAP-Response/Identity from client")
            else:
                logging.error("Failed to receive packet after EAP-Request/Identity")
        else:
            logging.error("Received packet is not EAPOL-Start")
    else:
        logging.error("Failed to receive EAPOL-Start from client")

if __name__ == "__main__":
    iface = "ens160"  # Interface on the Authenticator
    handle_authenticator(iface)

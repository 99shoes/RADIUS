import ssl
from scapy.all import *
from scapy.layers.eap import EAPOL, EAP
import logging

logging.basicConfig(level=logging.DEBUG)

def eapol_start():
    eapol_start_frame = Ether(dst="00:50:56:a4:1d:a4") / EAPOL(version=3, type=1)
    logging.debug(f"EAPOL-Start Frame: {eapol_start_frame.show(dump=True)}")
    return eapol_start_frame

def eap_response_identity(username):
    eap_response_frame = (
        Ether(dst="00:50:56:a4:1d:a4") /  # Authenticator's MAC address
        EAPOL(version=3, type=0) /  # version 3 corresponds to 2010
        EAP(code=2, id=1, type=1) /
        username.encode()  # Include username in the Identity field
    )
    logging.debug(f"EAP-Response/Identity Frame:\n {eap_response_frame.show(dump=True)}")
    return eap_response_frame

def create_ssl_context(cert_path, key_path, ca_cert_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.load_verify_locations(cafile=ca_cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    logging.debug("SSL context created with client certificate and CA certificate.")
    return context

def eap_response_tls(context):#HERE
    # Perform a TLS handshake with the context to get the ClientHello message
    #with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="RADIUS Server") as sock:
        #sock.connect(("192.168.30.166", 1812))
    client_hello = b'\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03'  # This is a very simple mock of a ClientHello message
        #client_hello = sock.getpeercert(True)  # 這將獲取 ClientHello 訊息

    eap_tls_client_hello_frame = (
        Ether(dst="00:50:56:a4:1d:a4", src="00:50:56:a4:86:3a") /  # 確認 src 和 dst MAC 地址正確
        EAPOL(type=0) /
        EAP(code=2, id=1, type=13, len=5 + len(client_hello)) /
        client_hello
    )
    logging.debug(f"EAP-TLS Client Hello Frame: {eap_tls_client_hello_frame.show(dump=True)}")
    return eap_tls_client_hello_frame

def send_eapol_start(iface):
    frame = eapol_start()
    logging.debug(f"Sending EAPOL-Start Frame on {iface}")
    logging.debug(f"Sending {frame}")
    sendp(frame, iface=iface)

def send_eap_response_identity(iface, username):
    frame = eap_response_identity(username)
    logging.debug(f"Sending EAP-Response/Identity Frame on {iface}")
    sendp(frame, iface=iface)
    logging.debug("EAP-Response/Identity Frame sent, waiting for EAP-Request/TLS...")

def receive_eap_request_identity(iface):
    max_retries = 3
    retry_count = 0
    while retry_count < max_retries:
        response = sniff(iface=iface, count=5, timeout=30, filter="ether proto 0x888e")
        if response:
            logging.debug(f"Received packet: {response[0].summary()}")
            if EAP in response[0]:
                if response[0][EAP].code == 1 and response[0][EAP].type == 1:
                    logging.debug("Received EAP-Request/Identity from Authenticator")
                    return 'identity'
                elif response[0][EAP].code == 1 and response[0][EAP].type == 13:
                    logging.debug("Received EAP-Request/TLS from Authenticator")
                    return 'tls'
        retry_count += 1
        logging.debug(f"Retry {retry_count}/{max_retries}")
    logging.error("Failed to receive EAP-Request/Identity from Authenticator after multiple attempts")
    return None

def send_eap_response_tls(iface, context):
    logging.debug("Preparing to send EAP-TLS Client Hello Frame...") #ERROR
    frame = eap_response_tls(context)
    logging.debug(f"Sending EAP-TLS Client Hello Frame on {iface}")
    logging.debug(f"Received frame:{frame}")
    sendp(frame, iface=iface)
    logging.debug("EAP-TLS Client Hello Frame sent.")

if __name__ == "__main__":
    iface = "ens160"
    username = "ludy"
    cert_path = "/etc/ssl/certs2/incorrect_client.pem"
    key_path = "/etc/ssl/certs2/incorrect_client.key"
    ca_cert_path = "/etc/ssl/certs/ca.pem"

    try:
        context = create_ssl_context(cert_path, key_path, ca_cert_path)
        send_eapol_start(iface)
        print("context:",context)
        packet_type = receive_eap_request_identity(iface)
        if packet_type == 'identity':
            send_eap_response_identity(iface, username)
            logging.debug("Supplicant: Waiting for EAP-Request/TLS after sending identity...")
            packet_type = receive_eap_request_identity(iface)
            logging.debug(f"packet type after sending identity: {packet_type}")
        
        if packet_type == 'tls':
            send_eap_response_tls(iface, context)
        
        logging.debug("EAP-TLS flow completed")
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
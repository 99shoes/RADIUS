# RADIUS
Supplicant->Authenticator->RADIUS coding

# Purpose
O-RAN.WG11.Security-Test-Specifications-v04
實作 11 Security test of Open Fronthaul
完成Supplicant Validation四種測驗項目
11.2.2 STC-11-11.2-002: Supplicant Validation
Requirement Name: Supplicant function of O-RAN component
Requirement Reference: Clause 5.2.5.5.2, O-RAN Security Requirements Specifications 4.0 [5]
Requirement Description: Requirements of Supplicant in the open fronthaul network
Threat References: T-FRHAUL-02
O-RAN Component References: O-DU, O-RU
11.2.2.1 Test description and applicability
Open fronthaul network component (such as O-RU and O-DU) shall support supplicant role of the 
802.1X for port-based network access control. This test validates the supplicant requirement of the 
network component for port connection request using EAP TLS authentication per 802.1X-2020 
[11].
11.2.2.2 Test setup and configuration
DUT shall be the O-RAN component with 802.1X enabled on its open fronthaul interface.
First set up an authentication RADIUS2 server (e.g. free radius on Linux) with root, server and client 
certificates configured with .cnf files and eap configuration (eap.conf). Then start the 
authentication RADIUS server.
11.2.2.3 Test procedure
First set up the 802.1X test tool host/device as the authenticator with EAP TLS authentication for 
802.1X protocol and configure the preset RADIUS server as its authentication server. Then start the 
test run as an emulated authenticator waiting for the supplicant request.
Configure and enable the O-RAN component of the open fronthaul interface to start the port 
connection request as a supplicant towards the 802.1X test tool, which is the authenticator. Verify
the 802.1X authentication process runs to completion.
The following test scenarios shall be covered for validation:
1. O-RAN component (as supplicant) setting for 802.1X with EAPoL, correct Identity 
(Certificate DN) and Client Certificate (provisioned on the Radius server)
2. O-RAN component (as supplicant) setting for 802.1X with EAPoL, correct Identity 
(Certificate DN) and incorrect Client Certificate (un-provisioned on the Radius server)
3. O-RAN component (as supplicant) setting for 802.1X with EAPoL and incorrect Identity (Certificate DN)
4. O-RAN component (as supplicant) setting for 802.1X with EAP non-TLS (e.g. MD5) 
authentication (optional)
11.2.2.4 Test requirements (expected results)
The O-RAN component shall be granted or denied the 802.1X port-based network access request 
as the supplicant with successful or failed EAP authentication per test scenarios listed above:
1. Successful RADIUS authentication by the authentication server;
2. Failed RADIUS authentication (wrong certificate) by the authentication server;
3. Failed RADIUS authentication (wrong Identity) by the authentication server;
4. Failed RADIUS authentication (wrong authentication type) by the authentication server;
# RADIUS Flow Chart ref by RFC2716
```js

Authenticating peer     NAS                    RADIUS server
-------------------     ---                    -------------
                        <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS Start, S bit set)
EAP-Response/
   EAP-Type=EAP-TLS
   (TLS client_hello) ->
                        RADIUS Access-Request/
                           EAP-Message/EAP-Response/
                           EAP-Type=EAP-TLS ->
                                              <- RADIUS Access-Challenge/
                                                 EAP-Message/
                                                 EAP-Request/
                                                 EAP-Type=EAP-TLS
                        <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS server_hello,
                            TLS certificate,
                            [TLS server_key_exchange,]
                            [TLS certificate_request,]
                            TLS server_hello_done)
EAP-Response/
   EAP-Type=EAP-TLS
   (TLS certificate,
    TLS client_key_exchange,
    [TLS certificate_verify,]
    TLS change_cipher_spec,
    TLS finished) ->
                        RADIUS Access-Request/
                           EAP-Message/EAP-Response/
                           EAP-Type=EAP-TLS ->
                                              <- RADIUS Access-Challenge/
                                                 EAP-Message/
                                                 EAP-Request/
                                                 EAP-Type=EAP-TLS
                        <- EAP-Request/
                           EAP-Type=EAP-TLS
                           (TLS change_cipher_spec,
                            TLS finished)
EAP-Response/
   EAP-Type=EAP-TLS ->
                        RADIUS Access-Request/
                           EAP-Message/EAP-Response/
                           EAP-Type=EAP-TLS ->
                                              <- RADIUS Access-Accept/
                                                 EAP-Message/EAP-Success
                                                 (other attributes)
                        <- EAP-Success
```

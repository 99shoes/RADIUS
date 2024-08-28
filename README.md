# RADIUS

**Implementation Flow**: Supplicant → Authenticator → RADIUS Coding

## Purpose

根據 **O-RAN.WG11.Security-Test-Specifications-v04**，實作 Open Fronthaul 的安全測試，完成 Supplicant Validation 的四種測試項目。


## Test Item Details

- **Test Item Name**: Supplicant Validation
- **Requirement Name**: Supplicant Function of O-RAN Component
- **Requirement Reference**: O-RAN Security Requirements Specifications 4.0 [5], Clause 5.2.5.5.2
- **Requirement Description**: Requirements for Supplicant in the Open Fronthaul Network
- **Threat Reference**: T-FRHAUL-02
- **O-RAN Component Reference**: O-DU, O-RU

## Test Description and Applicability

Open Fronthaul network components (such as O-RU and O-DU) should support the role of Supplicant in the **802.1X** protocol for port-based network access control. This test validates the Supplicant functionality of the network component when initiating a port connection request using **EAP TLS** authentication, in compliance with **802.1X-2020 [11]**.

## Test Setup and Configuration

- **DUT (Device Under Test)**: The O-RAN component with **802.1X** enabled, with its Open Fronthaul interface being tested.
- **RADIUS Server**: Set up and start a RADIUS authentication server (e.g., FreeRADIUS on Linux), with root, server, and client certificates configured, along with relevant `.cnf` and `eap.conf` files.
- **Authenticator**: Use a host or device with the **802.1X** testing tool as the authenticator, configured to use **EAP TLS** authentication, and set the aforementioned RADIUS server as its authentication server.

## Test Procedure

1. **Set Up Authentication Environment**
   - Configure and start the RADIUS server, ensuring that all necessary certificates and configuration files are correctly set up.
   - Set up the **802.1X** testing tool as the authenticator, configured to use **EAP TLS** authentication.

2. **Execute Test**
   - Configure and enable the Open Fronthaul interface of the O-RAN component to start the port connection request as a Supplicant towards the authenticator.
   - Observe and document the entire **802.1X** authentication process to ensure it completes successfully or fails as expected.

## Test Scenarios

1. **Correct Identity and Certificate**
   - The O-RAN component uses the correct identity (Certificate DN) and a client certificate that is provisioned on the RADIUS server.
   - **Expected Result**: Successful RADIUS authentication, allowing network access.

2. **Correct Identity and Incorrect Certificate**
   - The O-RAN component uses the correct identity (Certificate DN) but an incorrect client certificate that is not provisioned on the RADIUS server.
   - **Expected Result**: RADIUS authentication fails, denying network access.

3. **Incorrect Identity**
   - The O-RAN component uses an incorrect identity (Certificate DN).
   - **Expected Result**: RADIUS authentication fails, denying network access.

4. **Incorrect Authentication Type (Optional)**
   - The O-RAN component uses a non-TLS EAP authentication method (e.g., MD5).
   - **Expected Result**: RADIUS authentication fails, denying network access.

## RADIUS Flow Chart ref by RFC2716
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

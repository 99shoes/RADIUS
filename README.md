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

                        Supplicant                Authenticator               RADIUS server
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

## Building
參照:https://docs.beamnetworks.dev/en/linux/networking/freeradius-install
要修改的文件:
/etc/freeradius/3.0底下的clients.conf、dictionary、certs
/etc/freeradius/3.0/mods-enabled底下的eap
/etc/freeradius/3.0/sites-enabled底下的default、inner-tunnel

## Certificate
### Authenticator
### 1. 生成伺服器的私鑰 (`server.key`)

```bash
openssl genpkey -algorithm RSA -out /etc/freeradius/3.0/certs/server.key -aes256 -pass pass:<YOUR_PASSWORD> -outform PEM -pkeyopt rsa_keygen_bits:2048
```

這個命令會生成一個使用 2048 位 RSA 加密的私鑰文件，並且會加密存儲這個密鑰。

### 2. 生成 CA 的私鑰和自簽名證書 (`ca.pem`)

```bash
openssl req -x509 -new -nodes -keyout /etc/freeradius/3.0/certs/ca.key -sha256 -days 3650 -out /etc/freeradius/3.0/certs/ca.pem -subj "/C=TW/ST=Taiwan/L=Taipei/O=MyOrg/OU=IT/CN=RADIUS"
```
這個命令會生成一個 CA 的私鑰和一個有效期為 10 年的自簽名證書。

### 3. 生成伺服器的 CSR (證書簽名請求) (`server.csr`)

```bash
openssl req -new -key /etc/freeradius/3.0/certs/server.key -out /etc/freeradius/3.0/certs/server.csr -subj "/C=TW/ST=Taiwan/L=Taipei/O=MyOrg/OU=IT/CN=my-radius-server"
```

這個命令會生成一個用於伺服器證書的 CSR 文件。

### 4. 使用 CA 簽署伺服器證書 (`server.pem`)

```bash
openssl x509 -req -in /etc/freeradius/3.0/certs/server.csr -CA /etc/freeradius/3.0/certs/ca.pem -CAkey /etc/freeradius/3.0/certs/ca.key -CAcreateserial -out /etc/freeradius/3.0/certs/server.pem -days 365 -sha256
```

這個命令使用 CA 的私鑰簽署伺服器證書，有效期為 1 年。

### 5. 生成 DH 參數文件 (`dh`)

```bash
openssl dhparam -out /etc/freeradius/3.0/certs/dh 2048
```

這個命令會生成 Diffie-Hellman 參數文件，通常用於強化 TLS 握手過程中的安全性。

### 6. 檢查文件權限

確保這些文件具有適當的權限，只有 FreeRADIUS 伺服器進程可以讀取這些文件：

```bash
chown freerad:freerad /etc/freeradius/3.0/certs/*
chmod 600 /etc/freeradius/3.0/certs/*
```

### 7. 重新啟動 FreeRADIUS 伺服器

在完成以上步驟後，重新啟動 FreeRADIUS 伺服器來使更改生效：

### Supplicant
### 1. 生成新的 CA 證書

```bash
要把Server的ca證書拿過來使用，重新生成會對不上
```

### 2. 生成客戶端證書的 CSR

```bash
openssl req -new -key client.key -out client.csr -subj "/C=TW/ST=Taipei/L=Taipei City/O=YourCompanyName/OU=IT/CN=ludy/emailAddress=ludy@example.com"
```

### 3. 使用新的 CA 證書簽署客戶端證書

```bash
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365 -sha256
```

### 4. 驗證客戶端證書

底下為dictionary文件的內容
ATTRIBUTE   User-Name                1       string
ATTRIBUTE   User-Password            2       string
ATTRIBUTE   CHAP-Password            3       string
ATTRIBUTE   NAS-IP-Address           4       ipaddr
ATTRIBUTE   NAS-Port                 5       integer
ATTRIBUTE   Service-Type             6       integer
ATTRIBUTE   Framed-Protocol          7       integer
ATTRIBUTE   Framed-IP-Address        8       ipaddr
ATTRIBUTE   Framed-IP-Netmask        9       ipaddr
ATTRIBUTE   Framed-Routing           10      integer
ATTRIBUTE   Filter-Id                11      string
ATTRIBUTE   Framed-MTU               12      integer
ATTRIBUTE   Framed-Compression       13      integer
ATTRIBUTE   Login-IP-Host            14      ipaddr
ATTRIBUTE   Login-Service            15      integer
ATTRIBUTE   Login-TCP-Port           16      integer
ATTRIBUTE   Reply-Message            18      string
ATTRIBUTE   Callback-Number          19      string
ATTRIBUTE   Callback-Id              20      string
ATTRIBUTE   Framed-Route             22      string
ATTRIBUTE   Framed-IPX-Network       23      integer
ATTRIBUTE   State                    24      string
ATTRIBUTE   Class                    25      string
ATTRIBUTE   Vendor-Specific          26      string
ATTRIBUTE   Session-Timeout          27      integer
ATTRIBUTE   Idle-Timeout             28      integer
ATTRIBUTE   Termination-Action       29      integer
ATTRIBUTE   Called-Station-Id        30      string
ATTRIBUTE   Calling-Station-Id       31      string
ATTRIBUTE   NAS-Identifier           32      string
ATTRIBUTE   Proxy-State              33      string
ATTRIBUTE   Login-LAT-Service        34      string
ATTRIBUTE   Login-LAT-Node           35      string
ATTRIBUTE   Login-LAT-Group          36      string
#ATTRIBUTE   Framed-AppleTalk-Zone    37      string
ATTRIBUTE   Framed-AppleTalk-Network 38      integer
ATTRIBUTE   CHAP-Challenge           60      string
ATTRIBUTE   NAS-Port-Type            61      integer
ATTRIBUTE   Port-Limit               62      integer
ATTRIBUTE   Login-LAT-Port           63      integer
ATTRIBUTE   EAP-Message              79      string
ATTRIBUTE   Message-Authenticator    80      string

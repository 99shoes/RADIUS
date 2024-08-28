# RADIUS
Supplicant->Authenticator->RADIUS coding

# Purpose
根據 O-RAN.WG11.Security-Test-Specifications-v04，實作 Open Fronthaul 的安全測試，完成 Supplicant Validation 的四種測試項目。

# 測試項目詳情
測試項目名稱: Supplicant Validation
需求名稱: O-RAN 元件的 Supplicant 功能
需求參考: O-RAN Security Requirements Specifications 4.0 [5] 第 5.2.5.5.2 條
需求描述: 開放前傳網絡中 Supplicant 的要求
威脅參考: T-FRHAUL-02
O-RAN 元件參考: O-DU, O-RU
測試描述與適用性
開放前傳網絡元件（如 O-RU 和 O-DU）應支援基於埠的網絡存取控制協議 802.1X 的 Supplicant 角色。本測試驗證網絡元件在使用 EAP TLS 驗證進行埠連接請求時的 Supplicant 功能，符合 802.1X-2020 [11] 的規範。

測試設置與配置
DUT（Device Under Test）: 啟用了 802.1X 的 O-RAN 元件，其開放前傳接口將被測試。
RADIUS 伺服器: 設置並啟動一個認證 RADIUS 伺服器（例如，在 Linux 上使用 FreeRADIUS），配置 root、server 和 client 證書，以及相關的 .cnf 和 eap.conf 文件。
Authenticator: 使用 802.1X 測試工具的主機或設備作為驗證器，配置為使用 EAP TLS 驗證，並將上述 RADIUS 伺服器設為其認證伺服器。
測試流程
設置驗證環境

配置並啟動 RADIUS 伺服器，確保所有必要的證書和配置文件已正確設置。
設置 802.1X 測試工具作為驗證器，並配置使用 EAP TLS 驗證。
執行測試

配置並啟用 O-RAN 元件的開放前傳接口，作為 Supplicant 向驗證器發起埠連接請求。
觀察並記錄整個 802.1X 驗證過程，確保流程順利完成或按照預期失敗。
測試場景
正確的身份與證書

O-RAN 元件使用正確的身份（Certificate DN）和已在 RADIUS 伺服器上配置的客戶端證書。
預期結果: RADIUS 認證成功，允許網絡存取。
正確的身份與錯誤的證書

O-RAN 元件使用正確的身份（Certificate DN）但使用未在 RADIUS 伺服器上配置的客戶端證書。
預期結果: RADIUS 認證失敗，拒絕網絡存取。
錯誤的身份

O-RAN 元件使用錯誤的身份（Certificate DN）。
預期結果: RADIUS 認證失敗，拒絕網絡存取。
錯誤的認證類型（可選）

O-RAN 元件使用非 TLS 的 EAP 驗證方式（例如 MD5）。
預期結果: RADIUS 認證失敗，拒絕網絡存取。

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

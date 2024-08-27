# RADIUS
Supplicant->Authenticator->RADIUS coding

# RADIUS Flow Chart ref by RFC2716
 In the case where the NAS initiates with an EAP-Request for EAP TLS
   [RFC2716], and the identity is determined based on the contents of
   the client certificate, the exchange will appear as follows:

Authenticating peer     NAS                    RADIUS server
-------------------     ---                    -------------
                        <- EAP-Request/
                        EAP-Type=EAP-TLS
                        (TLS Start, S bit set)
EAP-Response/
EAP-Type=EAP-TLS
(TLS client_hello)->
                        RADIUS Access-Request/
                        EAP-Message/EAP-Response/
                        EAP-Type=EAP-TLS->
                                              <-RADIUS Access-Challenge/
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
TLS finished)->
                        RADIUS Access-Request/
                        EAP-Message/EAP-Response/
                        EAP-Type=EAP-TLS->
                                              <-RADIUS Access-Challenge/
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
                        EAP-Type=EAP-TLS->
                                              <-RADIUS Access-Accept/
                                              EAP-Message/EAP-Success
                                              (other attributes)
                        <- EAP-Success

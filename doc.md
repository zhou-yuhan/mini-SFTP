# SFTP Specification

From https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

## SSH connection

- server authentication
<- public key
<- private key encrypted public key

- data confidentialilty
-> public key encrypted symmetric key
(NOT using Diffie-Hellman key exchange)

*All packets should be tailed with MAC*
MAC = mac(symmetric key, unencrypted packet)

- client authentication
<- symmetric key encrypted msg
-> symmetric key encrypted password

## Data transfer

- general packet format
length type data

- protocol init
-> INIT
<- VERSION

- requests
-> OPEN
<- HANDLE (should not be interpreted by client, < 246B) or STATUS
    - with unique id
    - requests of the same file should be processed in order

- response
<- STATUS: id code
<- DATA
...

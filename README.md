# Specification

## SSH

From RFC 4251 4252 4253 4254

### Transport

#### Version Exchange

- The server MAY send other lines of data before sending the version
   string.  Each line SHOULD be terminated by a Carriage Return and Line Feed.
- identification string: SSH-protoversion-softwareversion SP comments CR LF

#### Binary Packet Protocol
```
uint32    packet_length 
byte      padding_length
byte[n1]  payload; n1 = packet_length - padding_length - 1
byte[n2]  random padding; n2 = padding_length
byte[m]   mac (Message Authentication Code - MAC); m = mac_length
```
- 'packet_length' does not include 'mac' or the
         'packet_length' field itself
- (packet_length || padding_length || payload || random padding)
         is a multiple of the cipher block size or 8, whichever is larger
- All implementations MUST be able to process packets with an
   uncompressed payload length of 32768 bytes or less and a total packet size of 35000 bytes or less (including 'packet_length',
   'padding_length', 'payload', 'random padding', and 'mac')

#### Encryption
- The ciphers in each direction MUST run independently of each other. In practice however, it is RECOMMENDED that the same
   algorithm be used in both directions.
- AES256-CBC

#### Integrity
- mac = MAC(key, sequence_number || unencrypted_packet)

- sequence_number is an implicit packet sequence number represented as uint32.  The sequence_number is initialized to zero for the first packet, and is incremented after every packet. The packet sequence_number itself is not included in the packet sent over the wire.

- The MAC algorithms for each direction MUST run independently, and implementations MUST allow choosing the algorithm independently for both directions. In practice however, it is RECOMMENDED that the same algorithm be used in both directions.

- hmac-sha1: digest length = key length = 20

#### Public Key
- format
```
string    certificate or public key format identifier
byte[n]   key/certificate data
```
- ssh-rsa
```
string    "ssh-rsa"
mpint     e
mpint     n
```

#### Algorithm Negotiation
- The key exchange method defined by this document uses explicit server authentication
- Kex format
```
    byte         SSH_MSG_KEXINIT
    byte[16]     cookie (random bytes)
    name-list    kex_algorithms
    name-list    server_host_key_algorithms
    name-list    encryption_algorithms_client_to_server
    name-list    encryption_algorithms_server_to_client
    name-list    mac_algorithms_client_to_server
    name-list    mac_algorithms_server_to_client
    name-list    compression_algorithms_client_to_server
    name-list    compression_algorithms_server_to_client
    name-list    languages_client_to_server
    name-list    languages_server_to_client
    boolean      first_kex_packet_follows
    uint32       0 (reserved for future extension)
```
- After receiving the SSH_MSG_KEXINIT packet from the other side,
         each party will know whether their guess was right.  If the
         other party's guess was wrong, and this field was TRUE, the
         next packet MUST be silently ignored, and both sides MUST then
         act as determined by the negotiated key exchange method.
- The key exchange produces two values: a shared secret K, and an exchange hash H.  Encryption and authentication keys are derived from these. The exchange hash H from the first key exchange is additionally used as the session identifier, which is a unique identifier for this connection.
- Encryption keys MUST be computed as a digest of the key exchange method specified hash

- Key exchange ends by each side sending an SSH_MSG_NEWKEYS message. This message is sent with the old keys and algorithms.

#### DH Key Exchange
- diffie-hellman-group1-sha1

#### Service Request
```
byte      SSH_MSG_SERVICE_REQUEST
string    service name ("ssh-userauth" or "ssh-connection")
```

#### Message Type Summary
```
SSH_MSG_DISCONNECT             1
SSH_MSG_IGNORE                 2
SSH_MSG_UNIMPLEMENTED          3
SSH_MSG_DEBUG                  4
SSH_MSG_SERVICE_REQUEST        5
SSH_MSG_SERVICE_ACCEPT         6
SSH_MSG_KEXINIT                20
SSH_MSG_NEWKEYS                21
```

### Authentication

#### Authentication Request
```
byte      SSH_MSG_USERAUTH_REQUEST
string    user name in ISO-10646 UTF-8 encoding [RFC3629]
string    service name in US-ASCII
string    method name in US-ASCII
....      method specific fields
```

#### Authentication Response
- success
    ```
    byte      SSH_MSG_USERAUTH_SUCCESS
    ```
- failure
    ```
    byte         SSH_MSG_USERAUTH_FAILURE
    name-list    authentications that can continue
    boolean      partial success
    ```

#### Banner
```
byte      SSH_MSG_USERAUTH_BANNER
string    message in ISO-10646 UTF-8 encoding [RFC3629]
string    language tag [RFC3066]
```

#### Message Type Summary
```
SSH_MSG_USERAUTH_REQUEST            50
SSH_MSG_USERAUTH_FAILURE            51
SSH_MSG_USERAUTH_SUCCESS            52
SSH_MSG_USERAUTH_BANNER             53
```

#### Authentication Methods
- passward
    ```
    byte      SSH_MSG_USERAUTH_REQUEST
    string    user name
    string    service name
    string    "password"
    boolean   FALSE
    string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
    ```

### Connection
#### Channel
- All terminal sessions, forwarded connections, etc., are channels.
   Either side may open a channel.  Multiple channels are multiplexed
   into a single connection.

#### Channel Open
```
byte      SSH_MSG_CHANNEL_OPEN
string    channel type in US-ASCII only ("session" for sftp)
uint32    sender channel
uint32    initial window size
uint32    maximum packet size
....      channel type specific data follows
```

#### Data Transfer

- flow control: adjust window
    ```
    byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
    uint32    recipient channel
    uint32    bytes to add
    ```

- send data
    ```
    byte      SSH_MSG_CHANNEL_DATA
    uint32    recipient channel
    string    data
    ```

#### Channel Close
```
byte      SSH_MSG_CHANNEL_EOF
uint32    recipient channel

byte      SSH_MSG_CHANNEL_CLOSE
uint32    recipient channel
```

#### Channel Request
```
byte      SSH_MSG_CHANNEL_REQUEST
uint32    recipient channel
string    "subsystem"
boolean   want reply
string    "sftp"
```

## SFTP

From https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

```c
sftp_new()
sftp_init()
sftp_[open|close|read|write]()
    sftp_packet_write()
        ssh_[channel_]write()
sftp_free()
```

## Build

```
cmake .. -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 -DCMAKE_C_COMPILER=/opt/homebrew/bin/gcc-11 -DCMAKE_CXX_COMPILER=/opt/homebrew/bin/g++-11 
```
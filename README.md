# SFTP Specification

From https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

## SSH connection

TBD

## Data transfer

```c
sftp_new()
sftp_init()
sftp_[open|close|read|write]()
    sftp_packet_write()
        ssh_[channel_]write()
sftp_free()
```
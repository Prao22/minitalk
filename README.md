# Minitalk
Minitalk is a tiny comunnicator with an encrypted communication. It is written in C. 
The encryption is programmed using the OpenSSL library.
Messages are encrypted by RSA and AES. Each client and server has its own RSA keys.
When **Client A** sends a message to **Client B**, **A** generates a AES key and iv and uses them to encrypt the message. Then **A** encrypts the AES key and the **B's** login using the server's public RSA key. 
**A** sends the message in a following format:
![](https://i.imgur.com/nps31DJ.png)
Server decodes the second part of the sent message by using its private RSA key, encrypts it again by using the **B's** public RSA key this time.
**B** receives the message and decodes it using his key.
### Build
Run make to build minitalk by gcc:
```sh 
make 
```

Configuring IP address or port of the server - in the 'sc_config.h' file.


```sh
# Run client:
./build/client
# Run server:
./build/server
```

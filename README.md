# SSH-Chatroom
Information Security Final Project

The present project endeavors to develop a secure chatroom based on the Secure Shell (SSH) protocol. Toward this end, a server is implemented that functions akin to a Kerberos Authentication Server (AS). Specifically, the server authenticates the clients who connect to it by verifying their RSA Public Key. Upon successful authentication, each client is assigned a public key by the server, which allows them to participate in the secure chatroom by using the SSH terminal. The overarching objective of this project is to establish a secure communication channel by employing a strong authentication mechanism that ensures only authorized users can access the chatroom.

The `Twisted` library is used for implementing the ssh protocols.

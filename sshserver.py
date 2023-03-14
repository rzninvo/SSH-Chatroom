from zope.interface import implementer
from twisted.conch import avatar, recvline
from twisted.conch.interfaces import IConchUser, ISession
from twisted.conch.ssh import factory, keys, session
from twisted.conch.insults import insults
from twisted.cred import portal, checkers
from twisted.internet import reactor
import os
from datetime import datetime


class SSHProtocol(recvline.HistoricRecvLine):
    """ SSH Protocol is the implementation of the things we want to do in our session with the client.
    SSH Protocols always contain: 
        1. connectionMade: Which is for when we establish a secure connection with the client
        2. connectionLost: Which is for when we lose our secure connection with the client
        3. dataReceived or lineReceived: Which is for when we receieve a data from our client
    Usually we can use the basic.Protocol for receiving simple lines. But in this example I have used recvline.HistoricRecvLine
    which can log the terminal line. 
    There are multiple ways of sending and receiving messages: 
        1. Protocol.terminal.write()
        2. Protocol.trasnport.write()
        3. Protocol.sendMsg()
    We are using a terminal for our example so we are going to use the first method of sending messages. 
    """
    def __init__(self, user):
       self.user = user
 
    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write("Welcome to the SSH Chatroom!")
        self.terminal.nextLine()
        self.command_help()
        self.showPrompt()
        self.user.realm.clients[self.user.username] = self
        with open('logfile.log', 'a') as f:
                f.write(f"Client[{self.user.username.decode('utf-8')}] connection success at {datetime.now()}\n")
 
    def connectionLost(self, reason):
        self.user.realm.clients.pop(self.user.username)
        if len(self.user.realm.clients) > 0:
            for client in self.user.realm.clients:
                self.user.realm.clients[client].terminal.write(f"Client[{self.user.username.decode('utf-8')}] disconnected!")
                self.user.realm.clients[client].terminal.nextLine()
                self.user.realm.clients[client].showPrompt()
        with open('logfile.log', 'a') as f:
            f.write(f"Client[{self.user.username.decode('utf-8')}] disconnected at {datetime.now()}\n")

    def showPrompt(self):
        self.terminal.write("$ ")
 
    def getCommandFunc(self, cmd):
        """Getting the implemented function from the command string."""
        return getattr(self, f'command_{cmd.decode("utf-8")}', None)

    def lineReceived(self, line):
        line = line.strip()
        if line:
            print(line)
            with open('logfile.log', 'a') as f:
                f.write(f"Client[{self.user.username.decode('utf-8')}]: {line} at {datetime.now()}\n")
            cmdAndArgs = line.split()
            cmd = cmdAndArgs[0]
            args = cmdAndArgs[1:]
            func = self.getCommandFunc(cmd)
            if func:
                try:
                    func(*args)
                except Exception as e:
                    self.terminal.write(f"Error: {e}")
                    self.terminal.nextLine()
            else:
                self.terminal.write("No such command!")
                self.terminal.nextLine()
        self.showPrompt()
 
    def command_help(self):
        """Showing the available commands based on the function names starting with command_"""
        publicMethods = filter(
            lambda funcname: funcname.startswith('command_'), dir(self))
        commands = [cmd.replace('command_', '', 1) for cmd in publicMethods]
        self.terminal.write(f"Commands: {' '.join(commands)}")
        self.terminal.nextLine()
 
    def command_echo(self, *args):
        self.terminal.write(b' '.join(args))
        self.terminal.nextLine()
 
    def command_send(self, *args):
        """Sending a message to all the connected clients in our realm."""
        self.user.realm.clients[args[0]].terminal.write(f"Message from Client[{self.user.username.decode('utf-8')}] : ")
        self.user.realm.clients[args[0]].terminal.write(b' '.join(args[1:]))
        self.user.realm.clients[args[0]].terminal.nextLine()


    def command_quit(self):
        self.terminal.write("Goodbye!")
        self.terminal.nextLine()
        self.terminal.loseConnection()
        self.user.realm.clients.pop(self.user.username)
        if len(self.user.realm.clients) > 0:
            for client in self.user.realm.clients:
                self.user.realm.clients[client].terminal.write(f"Client[{self.user.username.decode('utf-8')}] disconnected!")
                self.user.realm.clients[client].terminal.nextLine()
                self.user.realm.clients[client].showPrompt()
        with open('logfile.log', 'a') as f:
            f.write(f"Client[{self.user.username.decode('utf-8')}] disconnected at {datetime.now()}\n")
        
 
    def command_clear(self):
        self.terminal.reset()
 
@implementer(ISession)
class SSHAvatar(avatar.ConchUser):
    """SSHAvatar is the client object also known as a ConchUser. Every client has a channelLookUp and a subSystemLookup.
    channelLookup is a dictionary containing the sessions our client has."""
    def __init__(self, username, realm):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.realm = realm
        self.channelLookup.update({b'session': session.SSHSession})
 
    def openShell(self, protocol):
        serverProtocol = insults.ServerProtocol(SSHProtocol, self)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))
 
    def getPty(self, terminal, windowSize, attrs):
        return None
 
    def execCommand(self, protocol, cmd):
        raise NotImplementedError()
 
    def closed(self):
        pass
 
 
@implementer(portal.IRealm)
class SSHRealm(object):
    """ The Realm of our SSH Server. Every client connected to our server is within our server's realm."""
    clients = {}
    with open('logfile.log', 'w') as f:
                f.write(f"Initialized SSHRealm at {datetime.now()}\n")
    def requestAvatar(self, avatarId, mind, *interfaces):
        if IConchUser in interfaces:
            return interfaces[0], SSHAvatar(avatarId, self), lambda: None
        else:
            raise NotImplementedError("No supported interfaces found.")

def getRSAKeys():
    """Getting the public and private keys generated with the following command in the terminal: 
       >> ssh-keygen -t rsa -b 4096 -C "aut.ac.ir"
    """
    with open(f'C:\\Users\\{os.getlogin()}\\.ssh\\id_rsa') as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = keys.Key.fromString(data=privateBlob)
 
    with open(f'C:\\Users\\{os.getlogin()}\\.ssh\\id_rsa.pub') as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = keys.Key.fromString(data=publicBlob)
 
    return publicKey, privateKey
 
 
if __name__ == "__main__":
    """Setting up the SSHFactory. This constructor will handle all the authorizations and will store all the private and public 
       key datasets. Something like an AS(Authentication Service)."""
    sshFactory = factory.SSHFactory()
    sshFactory.portal = portal.Portal(SSHRealm())

    users = {'roham': b'123', 'parham': b'456'}
    sshFactory.portal.registerChecker(
        checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))

    pubKey, privKey = getRSAKeys()
    sshFactory.publicKeys = {b'ssh-rsa': pubKey}
    sshFactory.privateKeys = {b'ssh-rsa': privKey}

    reactor.listenTCP(22222, sshFactory)
    reactor.run()
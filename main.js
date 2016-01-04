var Session = require('freespeech-session').Session;
var CleartextServer = require('freespeech-session').CleartextServer;
var crypto = require('./freecrypt');

console.log('Generating post-quantum key....');
var serverKey = crypto.generateHybridKey(1024);
crypto.importKey(serverKey.exportPublic());

console.log('Test program for crypto library');

var server = new CleartextServer(function(portno){
    console.log('Your port number is '+portno);
    //Connect to self
    var loopbackClient = new CleartextServer(function(portno){});
    var client = loopbackClient.connect('127.0.0.1',portno);
    crypto.connectToEndpoint(client,serverKey,function(session){
        session.registerReceiveCallback(function(data){
            console.log(data.toString());
        });
        session.sendPacket(new Buffer('Hello from client!'));
    });
    
},function(session){
    crypto.negotiateServerConnection(session,serverKey,function(session){
        session.registerReceiveCallback(function(data){
            console.log(data.toString());
        });
        session.sendPacket(new Buffer('Hello from server!'));
        session.close();
    });
});

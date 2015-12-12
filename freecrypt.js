var NodeRSA = require('node-rsa');
var SessionJS = require('freespeech-session');
var Session = SessionJS.Session;
var crypto = require('crypto');

NodeRSA.prototype.thumbprint = function () {
    var pubbin = this.exportKey('pkcs8-public-der');
    var hash = crypto.createHash('sha256');
    hash.update(pubbin);
    return hash.digest('hex');
};


        var crypt = {
    /**
     * 
     * @param {Number} Generates an RSA encryption key
     * @returns {nm$_freecrypt.NodeRSA}
     */
    generateRSAKey:function(bits) {
        return new NodeRSA({b:bits});
    },
    

/**
 * Encrypt using AES encryption
 * @param {Buffer} key
 * @param {Buffer} data
 * @returns {Buffer}
 */
aesEncrypt:function(key,data){
        var iv = new Buffer(16);
        key.copy(iv);
        var cipher = crypto.createCipheriv('aes-256-cbc', key,iv);
        var encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return encrypted;
    },
    /**
 * Decrypt using AES encryption
 * @param {Buffer} key
 * @param {Buffer} data
 * @returns {Buffer}
 */
    aesDecrypt:function(key,data) {
        var iv = new Buffer(16);
    key.copy(iv);
    var cipher = crypto.createDecipheriv('aes-256-cbc', key,iv);
    var decrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return decrypted;
    },
    /**
     * Establishes an encrypted session with the specified endpoint.
     * @param {Session} parentSocket The session to use
     * @param {nm$_freecrypt.NodeRSA} publicKey The public key to use during authentication
     * @param {function(Session)} callback The function that is invoked with a new, encrypted session
     * @returns {undefined}
     */
    connectToEndpoint:function(parentSocket,publicKey,callback) {
        var retval = Session();

    crypto.randomBytes(4 + 32, function (er, rnd) {
        //Note: Buffers are not initialized to all-zeroes; they can be used as a source of non-secure cryptographic pseudo-randomness
        //although we need to be careful about accidentally leaking sensitive data.
        var recvCBHandle;
        
        var timeout = setTimeout(function () {
            parentSocket.unregisterReceiveCallback(recvCBHandle);
            callback(null);
        }, 2000);
        var packet = new Buffer(4 + 1 + 32 + 1);
        rnd.copy(packet, 0, 0, 4);
        packet[4] = 0;
        rnd.copy(packet, 4 + 1, 4);
        packet[4 + 1 + 32] = 1;
        var encKey = new Buffer(32);
        rnd.copy(encKey,0,4);
        var sessionEstablished = false;
        var sessionID;
        recvCBHandle = parentSocket.registerReceiveCallback(function (data) {
            try {
            if(sessionEstablished) {
                data = crypt.aesDecrypt(encKey,data);
                retval.decodePacket(data);
            }else {
                var packet = crypt.aesDecrypt(encKey,data);
                if(packet.readUInt32LE(0) == rnd.readUInt32LE(0)) {
                    if(packet[4] == 1) {
                      sessionID = packet.readUInt16LE(4+1);
                      retval.setSessionID(sessionID);
                        clearTimeout(timeout);
                      sessionEstablished = true;
                      var _send = retval.send;
                            retval.send = function(packet) {
                          _send(packet);
                          var alignedBuffer = new Buffer(Math.ceil(packet.length/16)*16);
                          packet.copy(alignedBuffer);
                              
                          parentSocket.send(crypt.aesEncrypt(encKey,alignedBuffer));
                      };
                            callback(retval);
                    }
                }
            }
        }catch(er) {
            console.log('DEBUG: Session server error '+er);
        }
        });
        //TODO: Encrypt before sending
        var key = new Buffer(32);
        rnd.copy(key, 0, 4);
        packet = publicKey.encrypt(packet);
        parentSocket.send(packet);

    });


    },
    /**
     * Negotiates an encrypted connection with a connected client
     * @param {Session} session
     * @param {nm$_freecrypt.NodeRSA} pubkey The public key to use during negotiation
     * @param {function(Session)} callback
     * @returns {undefined}
     */
    negotiateServerConnection:function(session,pubkey,callback) {
        console.log('DEBUG: Session start');
        var encryptedSession = Session();
            var _send = encryptedSession.send;
            var _close = encryptedSession.close;
            encryptedSession.send = function(data) {
                //Align data buffer
                _send(data);
                var alignedBuffer = new Buffer(Math.ceil(data.length/16)*16);
                data.copy(alignedBuffer);
                session.send(crypt.aesEncrypt(encryptedSession.key,alignedBuffer));
                
            };
            encryptedSession.close = function() {
                _close();
            };
            
        //We have a possible active connection
        session.registerReceiveCallback(function (data) {
            try {
                if (encryptedSession.key) {
                    //TODO: Use active session key
                    encryptedSession.decodePacket(crypt.aesDecrypt(encryptedSession.key,data));
                } else {
                    //Must be addressed to us, decode it
                    var packet = pubkey.decrypt(data);
                    //Opcode MUST be zero. If not, somebody's probably up to something....
                    if (packet[4] != 0) {
                        throw 'Illegal OPCODE';
                    }
                    //Get AES session key, and create crypto object for it
                    var aeskey = new Buffer(32);
                    packet.copy(aeskey, 0, 5, 5 + 32);
                    var includeIPInformation = packet[5 + 32];
                    encryptedSession.key = aeskey;
                    console.log('DEBUG: Session parsed');
                    //Send response to connection
                    var response = new Buffer(16);
                    //TODO: To prevent replay attacks, the first four bytes in this frame should match the random data
                    //in the initial handshake request.
                        packet.copy(response,0,0,4);
                        response[4] = 1;
                        response.writeUInt16LE(encryptedSession.getSessionID(),4+1);
                        //TODO: Optional IP and port numbers
                        console.log('DEBUG TODO add IP and port numbers here');
                        session.send(crypt.aesEncrypt(encryptedSession.key,response));
                        callback(encryptedSession);
                }
            } catch (er) {
                console.log('DEBUG SESSION ERR: '+er);
                session.close(); //Terminate session on error.
            }
        });
    },
    NodeRSA:NodeRSA
    
};
module.exports = crypt;
var NodeRSA = require('node-rsa');
var SessionJS = require('freespeech-session');
var Session = SessionJS.Session;
var crypto = require('crypto');
var ntru = require('ntrujs');
NodeRSA.prototype.thumbprint = function () {
    var pubbin = this.exportKey('pkcs8-public-der');
    var hash = crypto.createHash('sha256');
    hash.update(pubbin);
    return hash.digest('hex');
};

var addRSAExtensions = function(rsaobj) {
    var retval = rsaobj;
     retval.exportPublic = function() {
            var data = new Buffer(1);
            data[0] = 0; //RSA public key
            var bin = retval.exportKey('pkcs8-public-der');
            return Buffer.concat([data,bin],data.length+bin.length);
        };
        retval.exportPrivate = function() {
          var data = new Buffer(1);
          data[0] = 1; //RSA private key
          var bin = retval.exportKey('pkcs1-der');
          return Buffer.concat([data,bin],data.length+bin.length);
        };
        retval.isPrivate = function() {
            return !retval.isPublic(true);
        };
        
    return retval;
};
var addHybridExtensions = function(hybridkey){
    var retval = hybridkey;
    retval.exportPublic = function(){
            var binrsa = retval.rsa.exportKey('pkcs8-public-der');
            var data = new Buffer(1+4+binrsa.length+retval.ntru.public.length);
            data[0] = 2; //NTRU+RSA public key
            data.writeUInt32LE(binrsa.length,1);
            binrsa.copy(data,1+4);
            retval.ntru.public.copy(data,1+4+binrsa.length);
            return data;
        };
        retval.exportPrivate = function() {
            var binrsa = retval.rsa.exportKey('pkcs1-der');
            var data = new Buffer(1+4+binrsa.length+4+retval.ntru.private.length+retval.ntru.public.length);
            data[0] = 3; //NTRU+RSA private key
            data.writeUInt32LE(binrsa.length,1);
            binrsa.copy(data,1+4);
            data.writeUInt32LE(retval.ntru.private.length,1+4+binrsa.length);
            retval.ntru.private.copy(data,1+4+binrsa.length+4);
            retval.ntru.public.copy(data,1+4+binrsa.length+4+retval.ntru.private.length); 
           return data;
        };
        retval.encrypt = function(data) {
            return retval.rsa.encrypt(ntru.encrypt(data,retval.ntru.public));
        };
        retval.decrypt = function(data) {
            return ntru.decrypt(retval.rsa.decrypt(data),retval.ntru.private);
        };
        retval.isPrivate = function() {
            return retval.ntru.private != undefined;
        };
    return retval;
};


        var crypt = {
    /**
     * 
     * @param {Number} Generates an RSA encryption key
     * @returns {nm$_freecrypt.NodeRSA}
     */
    generateRSAKey:function(bits) {
        return addRSAExtensions(new NodeRSA({b:bits}));
    },
    generateHybridKey:function(rsaBits) {
        var retval = {};
        retval.rsa = crypt.generateRSAKey(rsaBits);
        retval.ntru = ntru.createKey();
        return addHybridExtensions(retval);
        
    },
    importKey:function(data) {
        //TODO: Try new opcodes, followed by legacy formats.
        try {
            var buffy = new Buffer(data.length-1);
            data.copy(buffy,0,1);
            switch(data[0]) {
                case 0:
                    //RSA public key
                    var rsa = new NodeRSA();
                    rsa.importKey(buffy,'pkcs8-public-der');
                    return addRSAExtensions(rsa);
                    break;
                case 1:
                    //RSA private key
                    var rsa = new NodeRSA();
                    rsa.importKey(buffy,'pkcs1-der');
                    addRSAExtensions(rsa);
                    return rsa;
                    break;
                case 2:
                    //NTRU+RSA public key
                    var retval = {};
                    var rsabuf = new Buffer(buffy.readUInt32LE(0));
                    buffy.copy(rsabuf,0,0,buffy.readUInt32LE(0));
                    retval.rsa = new NodeRSA();
                    retval.rsa.importKey(rsabuf,'pkcs8-public-der');
                    var ntrubuf = new Buffer(buffy.length-4-rsabuf.length);
                    retval.ntru = {public:ntrubuf};
                    buffy.copy(ntrubuf,0,4+rsabuf.length);
                    addHybridExtensions(retval);
                    return retval;
                    break;
                case 3:
                    //NTRU+RSA private key
                     var retval = {};
                     retval.rsa = new NodeRSA();
                     var rsalen = buffy.readUInt32LE(0);
                     retval.rsa.importKey(buffy.slice(4,4+rsalen),'pkcs1-der');
                     var privlen = buffy.readUInt32LE(4+rsalen);
                     retval.ntru = {private:buffy.slice(4+rsalen+4,4+rsalen+4+privlen)};
                     retval.ntru.public = buffy.slice(4+rsalen+4+privlen);
                     addHybridExtensions(retval);
                     return retval;
                    break;
            }
        }catch(er) {
            //Legacy key
            try {
            var rsa = new NodeRSA();
            rsa.importKey(data,'pkcs1-der');
            addRSAExtensions(rsa);
            return rsa;
        }catch(err) {
            var rsa = new NodeRSA();
            rsa.importKey(data,'pkcs8-public-der');
            addRSAExtensions(rsa);
            return rsa;
        }
        }
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
                    //Send response to connection
                    var response = new Buffer(16);
                    //TODO: To prevent replay attacks, the first four bytes in this frame should match the random data
                    //in the initial handshake request.
                        packet.copy(response,0,0,4);
                        response[4] = 1;
                        response.writeUInt16LE(encryptedSession.getSessionID(),4+1);
                        //TODO: Optional IP and port numbers
                        session.send(crypt.aesEncrypt(encryptedSession.key,response));
                        callback(encryptedSession);
                }
            } catch (er) {
                session.close(); //Terminate session on error.
            }
        });
    },
    NodeRSA:NodeRSA
    
};
module.exports = crypt;
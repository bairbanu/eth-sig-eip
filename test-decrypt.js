
//original decrypt function takes encrypted msg, and 
// Decrypt = async function (Encryptedmsg, privateKey){
// 	const decrypted = await ethCypto.decryptWithPrivateKey (privateKey, encryptedmsg);
	
// 	const decryptedPayload = JSON.parse(decrypted)
// 	console.log(decryptedPayload.message);
// }
var crypto = require("crypto");
var promise = typeof Promise === "undefined" ?
              require("es6-promise").Promise :
              Promise;
var secp256k1 = require("secp256k1")
var ecdh = require("./ecdh")

const e = { iv: '520f202afe4ab4a506c516b59ff23fcb',
  ephemPublicKey: '042e150e1d5eb888fe604d5052a767aea76f43e351dd698a89a96ae3da13501e5ff61b6225ea9af88e13aaccbca0c163785110c265c3d5e8adb0ff0a5ac803db9f',
  ciphertext: '541858a38724fe92deb9472b82909d43fb5fcda95db124dc4b298664f3d3878563f7243be561eddd8c029d92da2a8acfad6001c4829f567c6919d1a825813783bc9e4ca2f2d50d606a71abf061a4e34d7b9c9e1dc16daf350d801cd4be2476e42934203cd556b250126f938257c45ade2286bdd3560ca7185469a0630dedac42b78ed1010afc5a34f9e9a9bc53ea8a12e8aa01fd7e618e08fa7ac9afa87ac233381e545eb3138944eb6168b9ebcd6c8949e853278f56f3a4284bf9e94dfd0ba4',
  mac: 'e99e453885fe1eaac74d37f56b20da561806ec6bf74a81e66f32efea6f5ad80f' }

const pk = '0x7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816';

var decrypt = async function (encryptedMsg, privateKey){
    const decrypted = await decryptWithPrivateKey (privateKey, encryptedMsg);
    
    const decryptedPayload = JSON.parse(decrypted)
    console.log(decryptedPayload.message);
}



// decryptWithPrivateKey function
//import eccrypto 
export default async function decryptWithPrivateKey(privateKey, encrypted) {

    // remove trailing '0x' from privateKey
    const twoStripped = privateKey.replace(/^.{2}/g, '');

    const encryptedBuffer = {
        iv: new Buffer(encrypted.iv, 'hex'),
        ephemPublicKey: new Buffer(encrypted.ephemPublicKey, 'hex'),
        ciphertext: new Buffer(encrypted.ciphertext, 'hex'),
        mac: new Buffer(encrypted.mac, 'hex')
    };

    const decryptedBuffer = await eccdecrypt(
        new Buffer(twoStripped, 'hex'),
        encryptedBuffer
    );
    return decryptedBuffer.toString();
}

//eccrypto.decrypt
// var promise = require promise;

// secp256k1 = require("secp256k1")
//ecdh = require("./build/Release/ecdh")

function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

var derive = function(privateKeyA, publicKeyB) {
  return new promise(function(resolve) {
    resolve(ecdh.derive(privateKeyA, publicKeyB));
  });
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

eccdecrypt = function(privateKey, opts) {
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    var hash = sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext
    ]);
    var realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC");
    return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
};

decrypt(e, pk);
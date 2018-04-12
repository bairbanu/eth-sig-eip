const ethUtil = require('ethereumjs-util')
const ethAbi = require('ethereumjs-abi')
const mmcrypto = require("./meta-mask-crypto.js") 

// const encryptedData = { iv: '520f202afe4ab4a506c516b59ff23fcb',
//   ephemPublicKey: '042e150e1d5eb888fe604d5052a767aea76f43e351dd698a89a96ae3da13501e5ff61b6225ea9af88e13aaccbca0c163785110c265c3d5e8adb0ff0a5ac803db9f',
//   ciphertext: '541858a38724fe92deb9472b82909d43fb5fcda95db124dc4b298664f3d3878563f7243be561eddd8c029d92da2a8acfad6001c4829f567c6919d1a825813783bc9e4ca2f2d50d606a71abf061a4e34d7b9c9e1dc16daf350d801cd4be2476e42934203cd556b250126f938257c45ade2286bdd3560ca7185469a0630dedac42b78ed1010afc5a34f9e9a9bc53ea8a12e8aa01fd7e618e08fa7ac9afa87ac233381e545eb3138944eb6168b9ebcd6c8949e853278f56f3a4284bf9e94dfd0ba4',
//   mac: 'e99e453885fe1eaac74d37f56b20da561806ec6bf74a81e66f32efea6f5ad80f' }

// const pivkey = '0x7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816';

module.exports = {

  concatSig: function (v, r, s) {
    const rSig = ethUtil.fromSigned(r)
    const sSig = ethUtil.fromSigned(s)
    const vSig = ethUtil.bufferToInt(v)
    const rStr = padWithZeroes(ethUtil.toUnsigned(rSig).toString('hex'), 64)
    const sStr = padWithZeroes(ethUtil.toUnsigned(sSig).toString('hex'), 64)
    const vStr = ethUtil.stripHexPrefix(ethUtil.intToHex(vSig))
    return ethUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex')
  },

  normalize: function (input) {
    if (!input) return

    if (typeof input === 'number') {
      const buffer = ethUtil.toBuffer(input)
      input = ethUtil.bufferToHex(buffer)
    }

    if (typeof input !== 'string') {
      var msg = 'eth-sig-util.normalize() requires hex string or integer input.'
      msg += ' received ' + (typeof input) + ': ' + input
      throw new Error(msg)
    }

    return ethUtil.addHexPrefix(input.toLowerCase())
  },

  personalSign: function (privateKey, msgParams) {
    var message = ethUtil.toBuffer(msgParams.data)
    var msgHash = ethUtil.hashPersonalMessage(message)
    var sig = ethUtil.ecsign(msgHash, privateKey)
    var serialized = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  recoverPersonalSignature: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    const sender = ethUtil.publicToAddress(publicKey)
    const senderHex = ethUtil.bufferToHex(sender)
    return senderHex
  },

  extractPublicKey: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    return '0x' + publicKey.toString('hex')
  },

  typedSignatureHash: function (typedData) {
    const hashBuffer = typedSignatureHash(typedData)
    return ethUtil.bufferToHex(hashBuffer)
  },

  signTypedData: function (privateKey, msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const sig = ethUtil.ecsign(msgHash, privateKey)
    return ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
  },

  recoverTypedSignature: function (msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const publicKey = recoverPublicKey(msgHash, msgParams.sig)
    const sender = ethUtil.publicToAddress(publicKey)
    return ethUtil.bufferToHex(sender)
  },

  decrypt: async function (encryptedMsg, privateKey){
    const decrypted = await mmcrypto.decryptWithPrivateKey (privateKey, encryptedMsg);
    
    const decryptedPayload = JSON.parse(decrypted)
    return decryptedPayload.message;
  },

  encrypt: async function (senderprivateKey, recieverPublicKey, msgParams){
    //first sign message
    // var privateKey = ethUtil.toBuffer(senderprivateKey)
    // var message = ethUtil.toBuffer(msgParams.data)
    // var msgHash = ethUtil.hashPersonalMessage(message)
    // var sig = ethUtil.ecsign(msgHash, privateKey)
    // var signature = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))

    var signature = function keccak256(params) {
        if (!Array.isArray(params)) {
            params = [{
                type: 'string',
                value: params
            }];
        }
        return ethAbi.soliditySha3(...params);
    }

    

    // then create payload
    const payload = {
      message: msgParams.data,
      signature
    };

    //then encrypt
    const encrypted = await mmcrypto.encryptWithPublicKey(
      recieverPublicKey, // by encryping with bobs publicKey, only bob can decrypt the payload with his privateKey
      JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
    );

    return encrypted;

  }

}



/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array')
  if (typeof typedData !== 'object' || !typedData.length) throw error

  const data = typedData.map(function (e) {
    return e.type === 'bytes' ? ethUtil.toBuffer(e.value) : e.value
  })
  const types = typedData.map(function (e) { return e.type })
  const schema = typedData.map(function (e) {
    if (!e.name) throw error
    return e.type + ' ' + e.name
  })

  return ethAbi.soliditySHA3(
    ['bytes32', 'bytes32'],
    [
      ethAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
      ethAbi.soliditySHA3(types, data)
    ]
  )
}

function recoverPublicKey(hash, sig) {
  const signature = ethUtil.toBuffer(sig)
  const sigParams = ethUtil.fromRpcSig(signature)
  return ethUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s)
}

function getPublicKeyFor (msgParams) {
  const message = ethUtil.toBuffer(msgParams.data)
  const msgHash = ethUtil.hashPersonalMessage(message)
  return recoverPublicKey(msgHash, msgParams.sig)
}


function padWithZeroes (number, length) {
  var myString = '' + number
  while (myString.length < length) {
    myString = '0' + myString
  }
  return myString
}


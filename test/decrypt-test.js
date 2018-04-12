const test = require("tape-async");
const sigUtil = require('../')

test('decrypt ECDSA encrypted text', async (t) => {
  t.plan(1)
  const originalText = "My name is Satoshi Buterin"
  const encryptedData = { iv: '520f202afe4ab4a506c516b59ff23fcb',
  ephemPublicKey: '042e150e1d5eb888fe604d5052a767aea76f43e351dd698a89a96ae3da13501e5ff61b6225ea9af88e13aaccbca0c163785110c265c3d5e8adb0ff0a5ac803db9f',
  ciphertext: '541858a38724fe92deb9472b82909d43fb5fcda95db124dc4b298664f3d3878563f7243be561eddd8c029d92da2a8acfad6001c4829f567c6919d1a825813783bc9e4ca2f2d50d606a71abf061a4e34d7b9c9e1dc16daf350d801cd4be2476e42934203cd556b250126f938257c45ade2286bdd3560ca7185469a0630dedac42b78ed1010afc5a34f9e9a9bc53ea8a12e8aa01fd7e618e08fa7ac9afa87ac233381e545eb3138944eb6168b9ebcd6c8949e853278f56f3a4284bf9e94dfd0ba4',
  mac: 'e99e453885fe1eaac74d37f56b20da561806ec6bf74a81e66f32efea6f5ad80f' }
  const privateKey = '0x7e5374ec2ef0d91761a6e72fdf8f6ac665519bfdf6da0a2329cf0d804514b816'; 
  const result = await sigUtil.decrypt(encryptedData, privateKey)
  console.log("RESULT IS:", result)
  t.equal(result, originalText)
})
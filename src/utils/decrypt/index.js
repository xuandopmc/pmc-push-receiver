const crypto = require('crypto');
const ece = require('http_ece');

module.exports = decrypt;

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
function decrypt(object, keys) {
  const cryptoKey = object.appData.find(item => item.key === 'crypto-key');
  if (!cryptoKey) throw new Error('crypto-key is missing');
  const salt = object.appData.find(item => item.key === 'encryption');
  if (!salt) throw new Error('salt is missing');

  const decodedCryptoKey = base64urlDecode(cryptoKey.value.slice(3));
  const decodedSalt = base64urlDecode(salt.value.slice(5));

  const dh = crypto.createECDH('prime256v1');
  dh.setPrivateKey(keys.privateKey, 'base64');

  const params = {
    version    : 'aesgcm',
    authSecret : keys.authSecret,
    dh         : decodedCryptoKey,
    privateKey : dh,
    salt       : decodedSalt,
  };

  const decrypted = ece.decrypt(object.rawData, params);
  return JSON.parse(decrypted);
}

function base64urlDecode(str) {
  str = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return Buffer.from(str, 'base64').toString('utf-8');
}

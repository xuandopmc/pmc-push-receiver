const crypto = require('crypto');
const ece = require('http_ece');

module.exports = decrypt;

// https://tools.ietf.org/html/draft-ietf-webpush-encryption-03
function base64UrlToBase64(base64UrlString) {
  // Replace URL-safe characters
  let base64 = base64UrlString.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if necessary
  while (base64.length % 4) {
    base64 += '=';
  }

  return base64;
}

function decrypt(object, keys) {
  if (!object || !keys) {
    throw new Error('Invalid input: object or keys are missing');
  }

  // Find and validate cryptoKey
  const cryptoKey = object.appData.find(item => item.key === 'crypto-key');
  if (!cryptoKey || !cryptoKey.value) {
    throw new Error('crypto-key is missing or invalid');
  }

  // Find and validate salt
  const salt = object.appData.find(item => item.key === 'encryption');
  if (!salt || !salt.value) {
    throw new Error('salt is missing or invalid');
  }

  // Convert cryptoKey and salt from base64url to base64
  const cryptoKeyBase64 = base64UrlToBase64(cryptoKey.value.slice(3));
  const saltBase64 = base64UrlToBase64(salt.value.slice(5));

  // Initialize ECDH with the private key
  const dh = crypto.createECDH('prime256v1');
  try {
    dh.setPrivateKey(keys.privateKey, 'base64');
  } catch (err) {
    console.error('Invalid private key format:', err.message);
    throw new Error('Failed to set private key');
  }

  // Convert dh, salt, and authSecret to Buffer manually to avoid "base64url" usage
  const params = {
    version    : 'aesgcm',
    authSecret : Buffer.from(base64UrlToBase64(keys.authSecret), 'base64'),
    dh         : Buffer.from(cryptoKeyBase64, 'base64'),
    privateKey : dh,
    salt       : Buffer.from(saltBase64, 'base64'),
  };

  try {
    // Perform the decryption
    const decrypted = ece.decrypt(object.rawData, params);
    return JSON.parse(decrypted);
  } catch (err) {
    console.error('Decryption failed:', err.message);
    throw new Error('Failed to decrypt the message');
  }
}

var sodium = require('sodium-universal')
var assert = require('nanoassert')

var APPTOKEN_BYTES_MIN = sodium.crypto_generichash_KEYBYTES_MIN
var APPTOKEN_BYTES = 18 // fits into base64 encoding without padding
var APPTOKEN_BYTES_MAX = sodium.crypto_generichash_KEYBYTES_MAX

// Why 18? Because 18 bytes > 128 bits, making an adversary do at least 2^64
// attempts before finding a hash collision, ie. being able to fake a token
// 18 is the first number after 16 (128 bits) where `x mod 6 = 0`,
// meaning it base64 encodes without padding
function create (size) {
  assert(size == null ? true : size >= APPTOKEN_BYTES, 'size must be at least APPTOKEN_BYTES (' + APPTOKEN_BYTES + ')')
  assert(size == null ? true : Number.isSafeInteger(size), 'size must be safe integer')

  var res = new Buffer(size || APPTOKEN_BYTES)
  sodium.randombytes_buf(res)
  return res
}

// namespace can be used to seperate different various token uses eg. session,
// access, deploy etc.
function hash (tokenBuf, namespace) {
  assert(Buffer.isBuffer(tokenBuf), 'tokenBuf must be Buffer')

  if (typeof namespace === 'string') {
    var bytes = Buffer.byteLength(namespace)
    assert(bytes >= APPTOKEN_BYTES_MIN, 'byteLength of namespace must at least APPTOKEN_BYTES_MIN (' + APPTOKEN_BYTES_MIN + ')')
    assert(bytes <= APPTOKEN_BYTES_MAX, 'byteLength of namespace must at most APPTOKEN_BYTES_MAX (' + APPTOKEN_BYTES_MAX + ')')
    namespace = Buffer.from(namespace)
  }

  assert(namespace == null ? true : Buffer.isBuffer(namespace), 'namespace must be Buffer')
  assert(namespace == null ? true : namespace.length >= APPTOKEN_BYTES_MIN, 'namespace must at least APPTOKEN_BYTES_MIN (' + APPTOKEN_BYTES_MIN + ')')
  assert(namespace == null ? true : namespace.length <= APPTOKEN_BYTES_MAX, 'namespace must at most APPTOKEN_BYTES_MAX (' + APPTOKEN_BYTES_MAX + ')')

  var output = new Buffer(sodium.crypto_generichash_BYTES)

  sodium.crypto_generichash(output, tokenBuf, namespace)
  return output
}

module.exports = {
  create: create,
  hash: hash,
  APPTOKEN_BYTES_MIN: APPTOKEN_BYTES_MIN,
  APPTOKEN_BYTES: APPTOKEN_BYTES,
  APPTOKEN_BYTES_MAX: APPTOKEN_BYTES_MAX
}

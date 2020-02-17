var sodium = require('sodium-universal')
var assert = require('nanoassert')

var APPTOKEN_BYTES_MIN = 16 // 128 bits
var APPTOKEN_BYTES = 18 // fits into base64 encoding without padding

// Why 18? Because 18 bytes > 128 bits, making an adversary do at least 2^64
// attempts before finding a hash collision, ie. being able to fake a token
// 18 is the first number after 16 (128 bits) where `x mod 6 = 0`,
// meaning it base64 encodes without padding
function create (size) {
  assert(size == null ? true : size >= APPTOKEN_BYTES_MIN, 'size must be at least APPTOKEN_BYTES_MIN (' + APPTOKEN_BYTES_MIN + ')')
  assert(size == null ? true : Number.isSafeInteger(size), 'size must be safe integer')

  var res = new Buffer(size || APPTOKEN_BYTES)
  sodium.randombytes_buf(res)
  return res
}

var EMPTY_BUF = Buffer.alloc(0)
// namespace can be used to seperate different various token uses eg. session,
// access, deploy etc.
function hash (tokenBuf, namespace) {
  assert(Buffer.isBuffer(tokenBuf), 'tokenBuf must be Buffer')

  if (namespace == null) namespace = EMPTY_BUF
  if (typeof namespace === 'string') namespace = Buffer.from(namespace)
  assert(namespace == null ? true : Buffer.isBuffer(namespace), 'namespace must be Buffer')

  var output = new Buffer(sodium.crypto_generichash_BYTES)

  sodium.crypto_generichash(output, Buffer.concat([namespace, tokenBuf]))
  return output
}

module.exports = {
  create,
  hash,
  APPTOKEN_BYTES_MIN,
  APPTOKEN_BYTES
}

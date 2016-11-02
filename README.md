# cipher-base

[![NPM Package](https://img.shields.io/npm/v/cipher-base.svg?style=flat-square)](https://www.npmjs.org/package/cipher-base)
[![Build Status](https://img.shields.io/travis/crypto-browserify/cipher-base.svg?branch=master&style=flat-square)](https://travis-ci.org/crypto-browserify/cipher-base)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

Abstract base class to inherit from if you want to create streams implementing the same API as node crypto [Cipher][1] or [Decipher][2] (for [Hash][3] check [crypto-browserify/hash-base][4]).

## Example

```js
const CipherBase = require('cipher-base')
const inherits = require('inherits')

// our cipher will apply XOR 0x42 to every byte
function MyCipher () {
  CipherBase.call(this, true) // for Deciper you need pass `false`
}

inherits(MyCipher, CipherBase)

MyCipher.prototype._isAuthenticatedMode = function () {
  return false
}

MyCipher.prototype._setAutoPadding = function (ap) {}
MyCipher.prototype._setAAD = function (aadbuf) {}

MyCipher.prototype._update = function (data) {
  const result = Buffer.allocUnsafe(data.length)
  for (let i = 0; i < data.length; ++i) result[i] = data[i] ^ 0x42
  return result
}

MyCipher.prototype._final = function () {
  return Buffer.allocUnsafe(0)
}

const data = Buffer.from([ 0x00, 0x42 ])
const cipher = new MyCipher()
console.log(Buffer.concat([cipher.update(data), cipher.final()]))
// => <Buffer 42 00>
```

## LICENSE

MIT

[1]: https://nodejs.org/api/crypto.html#crypto_class_cipher
[2]: https://nodejs.org/api/crypto.html#crypto_class_decipher
[3]: https://nodejs.org/api/crypto.html#crypto_class_hash
[4]: https://github.com/crypto-browserify/hash-base

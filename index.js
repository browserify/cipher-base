'use strict'
var Transform = require('stream').Transform
var inherits = require('inherits')
var StringDecoder = require('string_decoder').StringDecoder

var K_CIPHER = 0
var K_DECIPHER = 1

function throwIfNotStringOrBuffer (val, prefix) {
  if (!Buffer.isBuffer(val) && typeof val !== 'string') {
    throw new TypeError(prefix + ' must be a string or a buffer')
  }
}

function throwIfNotBuffer (val, prefix) {
  if (!Buffer.isBuffer(val)) throw new TypeError(prefix + ' must be a buffer')
}

function getDecoder (decoder, encoding) {
  decoder = decoder || new StringDecoder(encoding)
  if (decoder.encoding !== encoding) throw new Error('Cannot change encoding')
  return decoder
}

function CipherBase (chipher) {
  Transform.call(this)

  this._kind = chipher ? K_CIPHER : K_DECIPHER
  this._authTag = null
  this._decoder = null
  this._finalized = false
}

inherits(CipherBase, Transform)

CipherBase.prototype._isAuthenticatedMode = function () {
  throw new Error('_isAuthenticatedMode is not implemented')
}

CipherBase.prototype._transform = function (chunk, encoding, callback) {
  var error = null
  try {
    this.update(chunk, encoding)
  } catch (err) {
    error = err
  }

  callback(error)
}

CipherBase.prototype._flush = function (callback) {
  var error = null
  try {
    this.push(this.final())
  } catch (err) {
    error = err
  }

  callback(error)
}

CipherBase.prototype.update = function (data, inputEncoding, outputEncoding) {
  throwIfNotStringOrBuffer(data, 'Cipher data')
  if (this._finalized) throw new Error('Trying to add data in unsupported state')

  if (!Buffer.isBuffer(data)) data = Buffer.from(data, inputEncoding)

  data = this._update(data)
  if (outputEncoding && outputEncoding !== 'buffer') {
    this._decoder = getDecoder(this._decoder, outputEncoding)
    data = this._decoder.write(data)
  }
  return data
}

CipherBase.prototype._update = function () {
  throw new Error('_update is not implemented')
}

CipherBase.prototype.final = function (outputEncoding) {
  if (this._finalized) {
    var msg = this._isAuthenticatedMode()
      ? 'Unsupported state or unable to authenticate data'
      : 'Unsupported state'
    throw new Error(msg)
  }
  this._finalized = true

  var data = this._final()
  if (outputEncoding && outputEncoding !== 'buffer') {
    this._decoder = getDecoder(this._decoder, outputEncoding)
    data = this._decoder.end(data)
  }

  if (this._kind === K_DECIPHER && this._isAuthenticatedMode() && this._authTag !== null) {
    this._authTag.fill(0)
    this._authTag = null
  }

  return data
}

CipherBase.prototype._final = function (outputEncoding) {
  throw new Error('_final is not implemented')
}

CipherBase.prototype.setAutoPadding = function (ap) {
  if (this._finalized) {
    throw new Error('Attempting to set auto padding in unsupported state')
  }

  this._setAutoPadding(ap)
  return this
}

CipherBase.prototype._setAutoPadding = function (ap) {
  throw new Error('_setAutoPadding is not implemented')
}

CipherBase.prototype.getAuthTag = function () {
  if (this._kind !== K_CIPHER || this._authTag === null || !this._finalized) {
    throw new Error('Attempting to get auth tag in unsupported state')
  }

  return Buffer.from(this._authTag)
}

CipherBase.prototype.setAuthTag = function (tagbuf) {
  throwIfNotBuffer(tagbuf, 'Auth tag')
  if (!this._isAuthenticatedMode() || this._kind !== K_DECIPHER || this._finalized) {
    throw new Error('Attempting to set auth tag in unsupported state')
  }

  this._authTag = Buffer.from(tagbuf)
  return this
}

CipherBase.prototype.setAAD = function (aadbuf) {
  throwIfNotBuffer(aadbuf, 'AAD')
  if (!this._isAuthenticatedMode() || this._finalized) {
    throw new Error('Attempting to set AAD in unsupported state')
  }

  this._setAAD(aadbuf)
  return this
}

CipherBase.prototype._setAAD = function (aadbuf) {
  throw new Error('_setAAD is not implemented')
}

module.exports = CipherBase

'use strict'
var test = require('tape').test
var CipherBase = require('../')

var utf8text = 'УТФ-8 text'
var utf8buf = Buffer.from(utf8text, 'utf8')
function noop () {}

function createCipher (t) { t.cipher = new CipherBase(true) }
function createDeciper (t) { t.decipher = new CipherBase(false) }

function beforeEach (t) {
  var fns = Array.prototype.slice.call(arguments, 1)
  var _test = t.test
  t.test = function (name, callback) {
    _test(name, function (t) {
      for (var i = 0; i < fns.length; ++i) t = fns[i](t) || t
      callback(t)
    })
  }
}

test('CipherBase#_isAuthenticatedMode', function (t) {
  beforeEach(t, createCipher)

  t.test('is not implemented', function (t) {
    t.throws(function () {
      t.cipher._isAuthenticatedMode()
    }, /^Error: _isAuthenticatedMode is not implemented$/)
    t.end()
  })

  t.end()
})

test('CipherBase#_transform', function (t) {
  beforeEach(t, createCipher)

  t.test('should use CipherBase#update', function (t) {
    t.plan(4)
    t.cipher.update = function () {
      t.same(arguments.length, 2)
      t.same(arguments[0], utf8text)
      t.same(arguments[1], 'utf8')
    }
    t.cipher._transform(utf8text, 'utf8', function (err) {
      t.same(err, null)
    })
    t.end()
  })

  t.test('should handle error in CipherBase#update', function (t) {
    t.plan(1)
    var err = new Error('hey')
    t.cipher.update = function () { throw err }
    t.cipher._transform(Buffer.allocUnsafe(0), undefined, function (_err) {
      t.true(_err === err)
    })
    t.end()
  })

  t.end()
})

test('CipherBase#_flush', function (t) {
  beforeEach(t, createCipher)

  t.test('should use CipherBase#final', function (t) {
    t.plan(2)
    var buffer = Buffer.allocUnsafe(0)
    t.cipher.push = function (data) { t.true(data === buffer) }
    t.cipher.final = function () { return buffer }
    t.cipher._flush(function (err) { t.same(err, null) })
    t.end()
  })

  t.test('should handle errors in CipherBase#final', function (t) {
    t.plan(1)
    var err = new Error('hey')
    t.cipher.final = function () { throw err }
    t.cipher._flush(function (_err) { t.true(_err === err) })
    t.end()
  })

  t.end()
})

test('CipherBase#update', function (t) {
  beforeEach(t, createCipher)

  t.test('data should be buffer or string', function (t) {
    t.throws(function () {
      t.cipher.update(null)
    }, /^TypeError: Cipher data must be a string or a buffer$/)
    t.end()
  })

  t.test('should throw error after CipherBase#final', function (t) {
    t.cipher._final = noop
    t.cipher.final()
    t.throws(function () {
      t.cipher.update(Buffer.allocUnsafe(0))
    }, /^Error: Trying to add data in unsupported state$/)
    t.end()
  })

  t.test('should use CipherBase#_update', function (t) {
    t.plan(1)
    t.cipher._update = t.pass
    t.cipher.update(Buffer.allocUnsafe(0))
    t.end()
  })

  t.test('inputEncoding is utf8 by default', function (t) {
    t.plan(1)
    t.cipher._update = function (data) { t.same(data, utf8buf) }
    t.cipher.update(utf8text)
    t.end()
  })

  t.test('inputEncoding is defined', function (t) {
    t.plan(1)
    t.cipher._update = function (data) { t.same(data, utf8buf) }
    t.cipher.update(utf8buf.toString('hex'), 'hex')
    t.end()
  })

  t.test('outputEncoding is buffer by default', function (t) {
    t.cipher._update = function () { return Buffer.allocUnsafe(0) }
    var output = t.cipher.update(Buffer.allocUnsafe(0), undefined)
    t.true(Buffer.isBuffer(output))
    t.end()
  })

  t.test('outputEncoding is defined', function (t) {
    t.cipher._update = function () { return utf8buf }
    var output = t.cipher.update(Buffer.allocUnsafe(0), undefined, 'utf8')
    t.same(output, utf8text)
    t.end()
  })

  t.test('if outputEncoding is defined should be same as in previous time', function (t) {
    t.cipher._update = function () { return Buffer.allocUnsafe(0) }
    t.cipher.update(Buffer.allocUnsafe(0), undefined, 'utf8')
    t.throws(function () {
      t.cipher.update(Buffer.allocUnsafe(0), undefined, 'hex')
    }, /^Error: Cannot change encoding$/)
    t.end()
  })

  t.end()
})

test('CipherBase#_update', function (t) {
  beforeEach(t, createCipher)

  t.test('is not implemented', function (t) {
    t.throws(function () {
      t.cipher._update()
    }, /^Error: _update is not implemented$/)
    t.end()
  })

  t.end()
})

test('CipherBase#final', function (t) {
  beforeEach(t, createCipher, createDeciper)

  t.test('should throw error on second call', function (t) {
    t.plan(2)
    t.cipher._final = noop
    t.cipher._isAuthenticatedMode = function () { return true }
    t.cipher.final()
    t.throws(function () {
      t.cipher.final()
    }, /^Error: Unsupported state or unable to authenticate data$/)
    t.cipher._isAuthenticatedMode = function () { return false }
    t.throws(function () {
      t.cipher.final()
    }, /^Error: Unsupported state$/)
    t.end()
  })

  t.test('should call CipherBase#_final', function (t) {
    t.plan(1)
    t.cipher._final = t.pass
    t.cipher.final()
    t.end()
  })

  t.test('outputEncoding is buffer by default', function (t) {
    t.cipher._final = function () { return Buffer.allocUnsafe(0) }
    var output = t.cipher.final()
    t.true(Buffer.isBuffer(output))
    t.end()
  })

  t.test('outputEncoding is defined', function (t) {
    t.cipher._final = function () { return utf8buf }
    var output = t.cipher.final('utf8')
    t.same(output, utf8text)
    t.end()
  })

  t.test('if outputEncoding is defined should be same as in previous time', function (t) {
    t.cipher._update = function () { return Buffer.allocUnsafe(0) }
    t.cipher.update(Buffer.allocUnsafe(0), undefined, 'utf8')
    t.cipher._final = function () { return Buffer.allocUnsafe(0) }
    t.throws(function () {
      t.cipher.final('hex')
    }, /^Error: Cannot change encoding$/)
    t.end()
  })

  t.test('should destroy _authTag', function (t) {
    var tagbuf = Buffer.from([0x42])
    t.decipher._authTag = tagbuf // hack, because setAuthTag will throw error
    t.decipher._isAuthenticatedMode = function () { return true }
    t.decipher._final = noop
    t.decipher.final()
    t.same(tagbuf, Buffer.from([0x00]))
    t.same(t.decipher._authTag, null)
    t.end()
  })

  t.end()
})

test('CipherBase#_final', function (t) {
  beforeEach(t, createCipher)

  t.test('is not implemented', function (t) {
    t.throws(function () {
      t.cipher._final()
    }, /^Error: _final is not implemented$/)
    t.end()
  })

  t.end()
})

test('CipherBase#setAutoPadding', function (t) {
  beforeEach(t, createCipher)

  t.test('should throw error after CipherBase#final', function (t) {
    t.cipher._isAuthenticatedMode = noop
    t.cipher._final = noop
    t.cipher.final()
    t.throws(function () {
      t.cipher.setAutoPadding()
    }, /^Error: Attempting to set auto padding in unsupported state$/)
    t.end()
  })

  t.test('should call CipherBase#_setAutoPadding', function (t) {
    t.plan(1)
    t.cipher._setAutoPadding = t.pass
    t.cipher.setAutoPadding()
    t.end()
  })

  t.test('should return `this`', function (t) {
    t.cipher._setAutoPadding = noop
    t.equal(t.cipher.setAutoPadding(), t.cipher)
    t.end()
  })

  t.end()
})

test('CipherBase#_setAutoPadding', function (t) {
  beforeEach(t, createCipher)

  t.test('is not implemented', function (t) {
    t.throws(function () {
      t.cipher._setAutoPadding()
    }, /^Error: _setAutoPadding is not implemented$/)
    t.end()
  })

  t.end()
})

test('CipherBase#getAuthTag', function (t) {
  beforeEach(t, createCipher, adjustCipher, createDeciper)

  function adjustCipher (t) {
    t.cipher._authTag = Buffer.from(utf8buf)
    t.cipher._finalized = true
  }

  var errRegExp = /^Error: Attempting to get auth tag in unsupported state$/

  t.test('should throw error for decipher', function (t) {
    t.throws(function () {
      t.decipher.getAuthTag()
    }, errRegExp)
    t.end()
  })

  t.test('should throw error if auth tag is not defined', function (t) {
    t.cipher._authTag = null
    t.throws(function () {
      t.decipher.getAuthTag()
    }, errRegExp)
    t.end()
  })

  t.test('should throw error if called before CipherBase#final', function (t) {
    t.cipher._finalized = false
    t.throws(function () {
      t.decipher.getAuthTag()
    }, errRegExp)
    t.end()
  })

  t.test('should return auth tag', function (t) {
    var tagbuf = t.cipher.getAuthTag()
    t.same(tagbuf, utf8buf)
    t.end()
  })

  t.end()
})

// TODO
test('CipherBase#setAuthTag', function (t) {
  beforeEach(t, createCipher, createDeciper, adjustCipherDecipher)

  function adjustCipherDecipher (t) {
    t.cipher._isAuthenticatedMode = function () { return true }
    t.decipher._isAuthenticatedMode = function () { return true }
  }

  var errRegExp = /^Error: Attempting to set auth tag in unsupported state$/

  t.test('auth tag should be buffer', function (t) {
    t.throws(function () {
      t.decipher.setAuthTag(null)
    }, /^TypeError: Auth tag must be a buffer$/)
    t.end()
  })

  t.test('should throw error if is not authefication mode', function (t) {
    t.decipher._isAuthenticatedMode = function () { return false }
    t.throws(function () {
      t.decipher.setAuthTag(Buffer.allocUnsafe(0))
    }, errRegExp)
    t.end()
  })

  t.test('should throw error for cipher', function (t) {
    t.throws(function () {
      t.cipher.setAuthTag(Buffer.allocUnsafe(0))
    }, errRegExp)
    t.end()
  })

  t.test('should throw error if called after CipherBase#fianl', function (t) {
    t.decipher._final = noop
    t.decipher.final()
    t.throws(function () {
      t.decipher.setAuthTag(Buffer.allocUnsafe(0))
    }, errRegExp)
    t.end()
  })

  t.test('should set _authTag', function (t) {
    t.decipher.setAuthTag(utf8buf)
    t.same(t.decipher._authTag, utf8buf)
    t.end()
  })

  t.test('should return `this`', function (t) {
    t.equal(t.decipher.setAuthTag(Buffer.allocUnsafe(0)), t.decipher)
    t.end()
  })

  t.end()
})

test('CipherBase#setAAD', function (t) {
  beforeEach(t, createCipher)

  t.test('authefication data should be buffer', function (t) {
    t.throws(function () {
      t.cipher.setAAD(null)
    }, /^TypeError: AAD must be a buffer$/)
    t.end()
  })

  t.test('should throw error after CipherBase#final', function (t) {
    t.cipher._isAuthenticatedMode = function () { return true }
    t.cipher._final = noop
    t.cipher.final()
    t.throws(function () {
      t.cipher.setAAD(Buffer.allocUnsafe(0))
    }, /^Error: Attempting to set AAD in unsupported state$/)
    t.end()
  })

  t.test('should throw error if not authefication mode', function (t) {
    t.cipher._isAuthenticatedMode = function () { return false }
    t.throws(function () {
      t.cipher.setAAD(Buffer.allocUnsafe(0))
    }, /^Error: Attempting to set AAD in unsupported state$/)
    t.end()
  })

  t.test('should call CipherBase#_setAAD', function (t) {
    t.plan(1)
    t.cipher._isAuthenticatedMode = function () { return true }
    t.cipher._setAAD = t.pass
    t.cipher.setAAD(Buffer.allocUnsafe(0))
    t.end()
  })

  t.test('should return `this`', function (t) {
    t.cipher._isAuthenticatedMode = function () { return true }
    t.cipher._setAAD = noop
    t.equal(t.cipher.setAAD(Buffer.allocUnsafe(0)), t.cipher)
    t.end()
  })

  t.end()
})

test('CipherBase#_setAAD', function (t) {
  beforeEach(t, createCipher)

  t.test('is not implemented', function (t) {
    t.throws(function () {
      t.cipher._setAAD()
    }, /^Error: _setAAD is not implemented$/)
    t.end()
  })

  t.end()
})

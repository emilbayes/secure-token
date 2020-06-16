var test = require('tape')
var secureToken = require('.')

test('', function (assert) {
  var token = secureToken.create()

  assert.notOk(secureToken.hash(token).equals(token))
  assert.ok(secureToken.hash(token).equals(secureToken.hash(token)))
  assert.notOk(secureToken.hash(token, 'session').equals(secureToken.hash(token)))
  assert.end()
})

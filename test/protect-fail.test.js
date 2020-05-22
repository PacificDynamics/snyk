var applyPatch = require('../src/lib/protect/apply-patch');
var path = require('path');
var fs = require('fs');
var test = require('tap').test;
var snyk = require('../src/lib');

test('bad patch file does not apply', function(t) {
  // check the target file first
  var root = path.resolve(__dirname, './fixtures/semver-patch-fail/');
  var dir = path.resolve(root, './node_modules/semver');
  var semver = fs.readFileSync(dir + '/semver.js', 'utf8');
  t.ok('original semver loaded');

  var old = snyk.config.get('disable-analytics');
  snyk.config.set('disable-analytics', '1');

  applyPatch(
    root + '/363ce409-2d19-46da-878a-e059df2d39bb.snyk-patch',
    {
      source: dir,
      name: 'semver',
      version: '4.3.1',
      id: 'npm:semver:20150403',
      from: ['semver@4.3.1'],
    },
    true,
    'http://some.patch.url',
  )
    .then(function() {
      t.fail('patch successfully applied');
      fs.writeFileSync(dir + '/semver.js', semver);
    })
    .catch(function(error) {
      var semver2 = fs.readFileSync(dir + '/semver.js', 'utf8');
      t.equal(semver, semver2, 'target was untouched');
      t.equal(error.code, 'FAIL_PATCH', 'patch failed, task exited correctly');
    })
    .then(function() {
      // clean up
      fs.unlinkSync(dir + '/semver.js.orig');
      fs.unlinkSync(dir + '/semver.js.rej');
      fs.unlinkSync(dir + '/test/big-numbers.js.orig');
      fs.unlinkSync(dir + '/test/big-numbers.js.rej');
      fs.writeFileSync(dir + '/semver.js', semver);
    })
    .then(function() {
      t.ok('clean up done');
    })
    .catch(function(e) {
      console.log(e);
      t.fail('clean up failed');
    })
    .then(function() {
      if (old === undefined) {
        snyk.config.delete('disable-analytics');
      } else {
        snyk.config.set('disable-analytics', old);
      }
      t.end();
    });
});

var HawkStrategy = require('../lib/strategy'),
  Hawk = require('hawk'),
  should = require('should');

var credentials = {
  key: 'abcd',
  algorithm: 'sha256',
  user: 'tito',
  id: 'dasd123'
};

var strategy = new HawkStrategy({ bewit: true }, function(id, done) {
  if (id === credentials.id) return done(null, credentials);
  return done(null, null);
});


describe('passport-hawk with bewit', function() {

  it('can authenticate a request with a correct header', function(testDone) {
    var bewit = Hawk.uri.getBewit('http://example.com:8080/resource/4?filter=a', {
      credentials: credentials,
      ttlSec: 60 * 5
    });
    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a&bewit=' + bewit
    };

    strategy.success = function(user) {
      user.should.eql('tito');
      testDone();
    };

    strategy.error = function() {
      testDone(new Error(arguments));
    };
    strategy.authenticate(req);
  });

  it('should properly fail with correct challenge code when using different url', function(testDone) {
    var bewit = Hawk.uri.getBewit('http://example.com:8080/resource/4?filter=a' + bewit, {
      credentials: credentials,
      ttlSec: 60 * 5
    });
    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a&bewit=' + bewit
    };
    strategy.error = function(challenge) {
      challenge.message.should.eql('Bad mac');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should call done with false when the id doesnt exist', function(testDone) {
    var bewit = Hawk.uri.getBewit('http://example.com:8080/foobar', {
      credentials: {
        id: '321321',
        key: 'dsa',
        algorithm: 'sha256'
      },
      ttlSec: 60 * 5
    });

    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a&bewit=' + bewit
    };

    strategy.error = function(challenge) {
      challenge.message.should.eql('Unknown credentials');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should call fail when url doesnt have a bewit', function(testDone) {

    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };

    strategy.fail = function(failure) {
      failure.should.eql('Missing authentication tokens');
      testDone();
    };
    strategy.authenticate(req);
  });
});

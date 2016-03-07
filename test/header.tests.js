var HawkStrategy = require('../lib/strategy'),
  Hawk = require('hawk'),
  should = require('should');

var credentials = {
  key: 'abcd',
  algorithm: 'sha256',
  user: 'tito',
  id: 'dasd123'
};

var strategy = new HawkStrategy(function(id, done) {
  if (id === credentials.id) return done(null, credentials);
  return done(null, null);
});

describe('passport-hawk', function() {
  it('can authenticate a request with a correct header', function(testDone) {
    var header = Hawk.client.header('http://example.com:8080/resource/4?filter=a', 'GET', { credentials: credentials });
    var req = {
      headers: {
        authorization: header.field,
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    strategy.success = function(user) {
      user.should.eql('tito');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should properly fail with correct challenge code when using different url', function(testDone) {
    var header = Hawk.client.header('http://example.com:8080/resource/4?filter=a', 'GET', { credentials: credentials });
    var req = {
      headers: {
        authorization: header.field,
        host: 'example.com:9090'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    strategy.error = function(challenge) {
      challenge.message.should.eql('Bad mac');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should call done with false when the id doesnt exist', function(testDone) {
    var testCredentials = {
      id: '321321',
      key: 'dsa',
      algorithm: 'sha256'
    }
    var authHeader = Hawk.client.header('http://example.com:8080/resource/4?filter=a', 'POST', { credentials: testCredentials });
    var req = {
      headers: {
        authorization: authHeader.field,
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };

    strategy.error = function(challenge) {
      challenge.message.should.eql('Unknown credentials');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should fail with a stale request', function(testDone) {
    var fixedHeader = 'Hawk id="dasd123", ts="1366220539", nonce="xVO62D", mac="9x+7TGN6VLRH8zX5PpwewpIzvf+mTt8m7PDQQW2NU/U="';
    var req = {
      headers: {
        authorization: fixedHeader,
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    strategy.error = function(challenge) {
      challenge.message.should.eql('Stale timestamp');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('can authenticate a request with options', function(testDone) {
    var header = Hawk.client.header('https://example.com/resource/4?filter=a', 'GET', { credentials: credentials });
    var req = {
      headers: {
        authorization: header.field,
        host: 'example.com:3000'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    var opts = { port: 443 };
    strategy.success = function(user) {
      user.should.eql('tito');
      testDone();
    };
    strategy.authenticate(req, opts);
  });
});

var HawkStrategy = require('../lib/strategy'),
  hawk = require('hawk');

var credentials = {
  key: 'abcd',
  algorithm: 'hmac-sha-256',
  user: 'tito',
  id: 'dasd123'
};

var strategy = new HawkStrategy(function(id, done) {
  if(id === credentials.id) return done(null, credentials);
  return done(null, null);
});


describe('passport-hawk', function() {

  it('can authenticate a request with a correct header', function(testDone) {
    var req = {
      headers: {
        authorization: hawk.getAuthorizationHeader(credentials, 'GET', '/resource/4?filter=a', 'example.com', 8080),
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    strategy.success = function(user) {
      user.should.eql('tito');
      testDone();
    };
    strategy.error = function() {
      testDone(arguments);
    };
    strategy.authenticate(req);
  });

  it('should properly fail with correct challenge code when using different url', function(testDone) {
    var req = {
      headers: {
        authorization: hawk.getAuthorizationHeader(credentials, 'GET', '/foobar', 'example.com', 8080),
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };
    strategy.fail = function(challenge) {
      challenge.should.eql('Bad mac');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should call done with false when the id doesnt exist', function(testDone) {
    var authHeader = hawk.getAuthorizationHeader({
      id: '321321',
      key: 'dsa',
      algorithm: 'hmac-sha-256'
    }, 'GET', '/resource/4?filter=a', 'example.com', 8080);

    var req = {
      headers: {
        authorization: authHeader,
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a'
    };

    strategy.fail = function(challenge) {
      challenge.should.eql('invalid_token');
      testDone();
    };
    strategy.authenticate(req);
  });
});
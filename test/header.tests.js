var HawkStrategy = require('../lib/strategy'),
  Hawk = require('hawk');

var credentials = {
  key: 'abcd',
  algorithm: 'sha256',
  user: 'tito',
  id: 'dasd123'
};

var strategy = new HawkStrategy(function(id, done) {
  if(id === credentials.id) return done(null, credentials);
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
    strategy.error = function() {
      console.log('alskjhslkhskjdhf');
      testDone(arguments);
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
    strategy.fail = function(challenge) {
      challenge.should.eql('Bad mac');
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

    strategy.fail = function(challenge) {
      challenge.should.eql('Unknown credentials');
      testDone();
    };
    strategy.authenticate(req);
  });
});
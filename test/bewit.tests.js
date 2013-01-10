var HawkStrategy = require('../lib/strategy'),
  hawk = require('hawk');

var credentials = {
  key: 'abcd',
  algorithm: 'hmac-sha-256',
  user: 'tito',
  id: 'dasd123'
};

var strategy = new HawkStrategy({bewit: true}, function(id, done) {
  if(id === credentials.id) return done(null, credentials);
  return done(null, null);
});


describe('passport-hawk with bewit', function() {

  it('can authenticate a request with a correct header', function(testDone) {
    var bewit = hawk.uri.getBewit(credentials, 
                      '/resource/4?filter=a', 
                      'example.com', 8080, 60 * 5);
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

    strategy.fail = strategy.error = function() {
      testDone(new Error(arguments));
    };
    strategy.authenticate(req);
  });

  it('should properly fail with correct challenge code when using different url', function(testDone) {
    var bewit = hawk.uri.getBewit(credentials, 
                      '/foobar', 
                      'example.com', 8080, 60 * 5);
    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a&bewit=' + bewit  
    };
    strategy.fail = function(challenge) {
      challenge.should.eql('Bad mac');
      testDone();
    };
    strategy.authenticate(req);
  });

  it('should call done with false when the id doesnt exist', function(testDone) {
    var bewit = hawk.uri.getBewit({
        id: '321321',
        key: 'dsa',
        algorithm: 'hmac-sha-256'
      }, '/foobar', 'example.com', 8080, 60 * 5);
  
    var req = {
      headers: {
        host: 'example.com:8080'
      },
      method: 'GET',
      url: '/resource/4?filter=a&bewit=' + bewit  
    };

    strategy.fail = function(challenge) {
      challenge.should.eql('Unknown credentials');
      testDone();
    };
    strategy.authenticate(req);
  });
});
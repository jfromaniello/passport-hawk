[Passport.js](http://passportjs.org/) stategy for the [Hawk authentication scheme](https://github.com/hueniverse/hawk).

[![Build Status](https://travis-ci.org/jfromaniello/passport-hawk.svg?branch=master)](https://travis-ci.org/jfromaniello/passport-hawk)

This module allows you to use Hawk as an authentication strategy with passport.

## Installation

	npm install passport-hawk

## Usage

~~~javascript
var HawkStrategy = require('passport-hawk');

passport.use('my-hawk-strategy', new HawkStrategy(function (id, done) {
  Users.findById(id, function (err, user){
    if(err) return done(err);
    done(null, {
      key: 		 user.secret,
      algorithm: 'sha256', // sha1 or sha256
      user:		 user
    });
  });
}));
~~~

then you can set ```my-hawk-strategy``` as a middlware in any route. For instance:

~~~javascript
  myExpressApp.use('/api', 
  	passport.authenticate('my-hawk-strategy', { session: false }));
~~~


### Bewit support

passport-hawk can be used to validate [bewit](https://github.com/hueniverse/hawk#bewit-usage-example):

~~~javascript
var HawkStrategy = require('passport-hawk');

passport.use('my-hawk-strategy', new HawkStrategy({ bewit: true }, function (id, done) {
  //..same as previous section
});
~~~

## License

MIT

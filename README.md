[Passport.js](http://passportjs.org/) stategy for the [Hawk authentication scheme](https://github.com/hueniverse/hawk).

This module allows you to use Hawk as an authentication strategy with passport.

## Installation

	npm install passport-hawk

## Usage

~~~javascript
var HawkStrategy = require('passport-hawk');

passport.use('my-hawk-strategy', new HawkStrategy(function (id, done) {
  Users.findById(id, function (err, user){
    if(err) return done(err);
    return {
      key: 		 user.secret,
      algorithm: 'hmac-sha-256',
      user:		 user
	};
  });
}));
~~~

then you can set ```my-hawk-strategy``` as a middlware in any route. For instance:

~~~javascript
  myExpressApp.use('/api', 
  	passport.authenticate('my-hawk-strategy', { session: false }));
~~~

## License

MIT
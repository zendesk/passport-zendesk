# passport-zendesk

Zendesk OAuth2 strategy for Passport.

## Install

    $ npm install passport-zendesk

## Usage

#### Configure Strategy

```javascript
var passport = require('passport');
var ZendeskStrategy = require('passport-zendesk').Strategy;

passport.use(new ZendeskStrategy({
    subdomain: 'yourZendeskSubdomain',
    clientID: 'yourClientIdentifier',
    clientSecret: 'yourClientSecret'
    callbackURL: 'https://www.example.net/auth/zendesk/callback',
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate(..., function (err, user) {
      done(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'zendesk'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```javascript
app.get('/auth/zendesk',
  passport.authenticate('zendesk'));

app.get('/auth/zendesk/callback',
  passport.authenticate('zendesk', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Examples

For a complete, working sample: [login example](https://github.com/alavers/passport-zendesk/tree/master/examples/login).

## Thanks

  - [Jared Hanson](http://github.com/jaredhanson)

## License
Copyright (c) 2014 Andrew Lavers. Licensed under the MIT license.

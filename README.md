# passport-zendesk

Zendesk OAuth2 strategy for [Passport](http://passportjs.org).

## Install

    $ npm install passport-zendesk

## Usage

#### Configuration

```javascript
var passport = require('passport');
var ZendeskStrategy = require('passport-zendesk').Strategy;

passport.use(new ZendeskStrategy({
    subdomain: 'yourZendeskSubdomain',
    clientID: 'yourClientIdentifier',
    clientSecret: 'yourClientSecret',
    callbackURL: 'https://www.example.net/auth/zendesk/callback',
  },
  function(accessToken, refreshToken, profile, done) {
    done(err, user);
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'zendesk'` strategy to
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

#### Using a Global Zendesk OAuth Client

If you've set up a global Zendesk OAuth Client and you wish to authenticate with multiple Zendesk subdomains, passport-zendesk will look for a subdomain parameter in the query string and the post body. Using the configuraiton specified above, a login link for example.zendesk.com would look like this:

```html
<a href="/auth/zendesk?subdomain=example">Login with example.zendesk.com</a>
```

You may also specify the subdomain explicitly in the authenticate() options:

```javascript
app.get('/auth/zendesk',
  passport.authenticate('zendesk', { subdomain: 'example'}));
```

## Examples

For a complete, working sample: [login example](https://github.com/radialpoint/passport-zendesk/tree/master/examples/login).

## Thanks

  - [Jared Hanson](http://github.com/jaredhanson)

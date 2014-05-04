'use strict';

/**
 * Module dependencies.
 */
var util = require('util');
var utils = require('./utils');
var url = require('url');
var OAuth2 = require('oauth').OAuth2;
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var AuthorizationError = require('passport-oauth').AuthorizationError;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Zendesk authentication strategy authenticates requests by delegating to
 * Zendesk using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `subdomain`     your Zendesk subdomain, e.g. {this_part}.zendesk.com
 *   - `clientID`      your Zendesk OAuth client's unique identifier
 *   - `clientSecret`  your Zendesk OAuth client's secret
 *   - `callbackURL`   URL to which Zendesk will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new ZendeskStrategy({
 *         subdomain: 'yoursubdomain',
 *         clientID: 'yourClientIdentifier',
 *         clientSecret: 'yourClientSecret'
 *         callbackURL: 'https://www.example.net/auth/zendesk/callback',
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.customHeaders = options.customHeaders || {};
  options.scope = options.scope || ['read'];
  options.sessionKey = options.sessionKey || 'oauth2:zendesk.com';

  OAuth2Strategy.call(this, options, verify);
  this._subdomain = options.subdomain;
  this._options = options;
  this.name = 'zendesk';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Cache a separate OAuth2 client for each zendesk subdomain
 */
Strategy.prototype._oauth2Map = {};
Strategy.prototype._oauth2ForSubdomain = function(subdomain) {
  var options = this._options;
  var baseUrl = '';
  var authorizationURL = 'https://' + subdomain + '.zendesk.com/oauth/authorizations/new';
  var tokenURL = 'https://' + subdomain + '.zendesk.com/oauth/tokens';
  
  if (!this._oauth2Map[subdomain]) {
    this._oauth2Map[subdomain] = new OAuth2(
      options.clientID,
      options.clientSecret,
      baseUrl,
      authorizationURL,
      tokenURL,
      options.customHeaders);
  }

  return this._oauth2Map[subdomain];
};

/**
 * Authenticate request by delegating to Facebook using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  var oauth2;
  var urlObj = url.parse(req.url, true);
  var subdomain;
  
  if (urlObj.query && urlObj.query.subdomain) {
    subdomain = urlObj.query.subdomain;
    req.session.subdomain = subdomain;
  } else {
    subdomain = req.session.subdomain || options.subdomain;
  }

  if (!subdomain) {
    this.error(new Error('A Zendesk subdomain was not specified in options, and not found in query parameters'));
  }
  oauth2 = this._oauth2ForSubdomain(subdomain);
  
  if (req.query && req.query.error) {
    if (req.query.error === 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }
  
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  
  if (req.query && req.query.code) {
    var code = req.query.code;
    
    if (this._state) {
      if (!req.session) { return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      
      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }
      
      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.redirect_uri = callbackURL;

    oauth2.getOAuthAccessToken(code, params,
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
        
        self._loadUserProfile(accessToken, subdomain, function(err, profile) {
          if (err) { return self.error(err); }
          
          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }
          
          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity === 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity === 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) { return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }
    
    var location = oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
Strategy.prototype._loadUserProfile = function(accessToken, subdomain, done) {
  var self = this;
  
  function loadIt() {
    return self.userProfile(accessToken, subdomain, done);
  }
  function skipIt() {
    return done(null);
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Retrieve user profile from Zendesk.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `zendesk`
 *   - `id`               the user's Zendesk ID
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Zendesk
 *   - `emails`           the user's email addresses
 *   - `photos`           the user's profile photos
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, subdomain, done) {
  this._oauth2.get('https://' + subdomain + '.zendesk.com/api/v2/users/me.json', accessToken, function(err, body) {
    var json;
    var profile = {};

    if (err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }

    try {
      json = JSON.parse(body);
    } catch (e) {
      return done(new Error('Failed to parse user profile', err));
    }

    if (!json.user) {
      return done(new Error('Unrecognized user profile format'));
    }

    profile.provider = 'zendesk';
    profile.id = json.user.id;
    profile.displayName = json.user.name;
    profile.profileUrl = json.url;
    profile.emails = [{value: json.user.email}];
    if (json.user.photo) {
      profile.photos = [{value: json.user.photo.content_url}];
    }
    
    profile._raw = body;
    profile._json = json;

    done(null, profile);

  });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
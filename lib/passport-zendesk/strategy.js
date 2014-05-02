'use strict';

/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
  InternalOAuthError = require('passport-oauth').InternalOAuthError;

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
  if (typeof options.subdomain !== 'string') {
    throw new Error('A zendesk subdomain must be specified in strategy options');
  }
  options.authorizationURL = options.authorizationURL || 'https://' + options.subdomain + '.zendesk.com/oauth/authorizations/new';
  options.tokenURL = options.tokenURL || 'https://' + options.subdomain + '.zendesk.com/oauth/tokens';
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.customHeaders = options.customHeaders || {};
  options.scope = options.scope || ['read'];

  OAuth2Strategy.call(this, options, verify);
  this.name = 'zendesk';
  this.subdomain = options.subdomain;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

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
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get('https://' + this.subdomain + '.zendesk.com/api/v2/users/me.json', accessToken, function(err, body) {
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
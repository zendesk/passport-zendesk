var fs = require('fs');

var mockSubdomain = 'subdomain';
var mockUser;

module.exports = {
  subdomain: mockSubdomain,
  authorizationURL: 'https://' + mockSubdomain + '.zendesk.com/oauth/authorizations/new',
  tokenURL: 'https://' + mockSubdomain + '.zendesk.com/oauth/tokens',
  getParsedUser: function() {
    return {
      provider: 'zendesk',
      id: 1234,
      displayName: 'John Doe',
      profileUrl: 'https://subdomain.zendesk.com/api/v2/users/1234.json',
      emails: [
        { value: 'jdoe@example.com' }
      ],
      photos: [
        { value: 'https://subdomain.zendesk.com/system/photos/1234/1234/__20__2_.JPG' }
      ],
      _raw: mockUser,
      _json: JSON.parse(mockUser)
    };
  },
  inject: function(strategy, done) {
    fs.readFile('test/data/user.json', 'utf8', function(err, data) {
      if (err) { return done(err); }
      mockUser = data;

      // Inject the mock oauth2 behavior
      strategy._createOauth2 = function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
        return {
          getOAuthAccessToken: function(code, options, callback) {
            return callback(null, 'mocktoken');
          },
          getAuthorizeUrl: function(params) {
            return authorizePath;
          },
          get: function(url, accessToken, callback) {
            callback(null, mockUser);
          }
        };
      };
      done();
    });
  }
};
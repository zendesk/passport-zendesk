const chai = require('chai');
const { expect } = chai;
const { passport } = require('./chai.passport.strategy');
const ZendeskStrategy = require('..');
const querystring = require('querystring');
const mock = require('./mock');

describe('Strategy with dynammic subdomain', function() {
  var strategy = new ZendeskStrategy({
      clientID: 'testclientid',
      clientSecret: 'testSecret'
    },
    function() {}
  );

  before(function(done) {
    mock.inject(strategy, done);
  });

  describe('with missing subdomain', function() {
    var err;

    var t = passport.use(strategy);

    before(function(done) {
      passport.use(strategy)
        .error(function(e){
          err = e;
          done();
        })
        .request(function(req) {
          req.session = {};
          req.query = {};
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.message).to.equal('A Zendesk subdomain was not specified in options and was not found in request parameters');
    });
  });

  describe('with subdomain specified in query', function() {
    var redirectUrl;

    before(function(done) {
      passport.use(strategy)
        .redirect(function(location){
          redirectUrl = location;
          done();
        })
        .request(function(req) {
          req.session = {};
          req.query = {};
          req.query.subdomain = mock.subdomain;
        })
        .authenticate();
    });

    it('should redirect to correct zendesk subdomain', function() {
      expect(redirectUrl).to.equal(mock.authorizationURL);
    })
  });

  describe('with subdomain specified in post body', function() {
    var redirectUrl;

    before(function(done) {
      passport.use(strategy)
        .redirect(function(location){
          redirectUrl = location;
          done();
        })
        .request(function(req) {
          req.session = {};
          req.body = querystring.stringify({subdomain: mock.subdomain});
        })
        .authenticate();
    });

    it('should redirect to correct zendesk subdomain', function() {
      expect(redirectUrl).to.equal(mock.authorizationURL);
    })
  });

  describe('with malicious subdomain containing # (token-endpoint injection)', function() {
    var capturedTokenURL;
    var authError;

    before(function(done) {
      var attackStrategy = new ZendeskStrategy(
        { clientID: 'testclientid', clientSecret: 'testSecret' },
        function(accessToken, refreshToken, profile, done) { done(null, profile); }
      );

      attackStrategy._createOauth2 = function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath) {
        capturedTokenURL = accessTokenPath;
        return {
          getOAuthAccessToken: function(code, options, callback) {
            callback(null, 'mocktoken', null, {});
          },
          get: function(url, accessToken, callback) {
            callback(null, JSON.stringify({ user: { id: 1, name: 'Test', url: '', email: 'test@test.com' } }));
          }
        };
      };

      passport.use(attackStrategy)
        .success(function() { done(); })
        .error(function(e) { authError = e; done(); })
        .request(function(req) {
          req.query = { subdomain: 'evil.com#', code: 'authcode' };
          req.session = {};
        })
        .authenticate();
    });

    it('should reject the request with an error', function() {
      expect(authError).to.be.an.instanceof(Error);
    });

    it('should not construct an OAuth2 client for the attacker domain', function() {
      expect(capturedTokenURL).to.equal(undefined);
    });
  });
});

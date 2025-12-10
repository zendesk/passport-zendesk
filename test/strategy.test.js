const chai = require('chai');
const { expect } = chai;
const ZendeskStrategy = require('..');
const mock = require('./mock');
const { passport } = require('./chai.passport.strategy');

describe('Strategy', function() {

  var strategy = new ZendeskStrategy({
      subdomain: mock.subdomain,
      clientID: 'testclientid',
      clientSecret: 'testSecret'
    },
    function(accessToken, refreshToken, profile, done) {
      return done(null, profile);
    }
  );

  before(function(done) {
    mock.inject(strategy, done);
  });

  it('should be named zendesk', function() {
    expect(strategy.name).to.equal('zendesk');
  });

  describe('requesting auth code', function() {
    var location;

    before(function(done) {

      passport.use(strategy)
        .redirect(function(l) {
          location = l;
          done();
        })
        .request(function(req) {
          req.query = {};
        })
        .authenticate();
    });

    it('should succeed', function() {
      expect(location).to.equal(mock.authorizationURL);
    })
  });

  describe('retrieving user profile', function() {
    var user;

    before(function(done) {

      passport.use(strategy)
        .success(function(u) {
          user = u;
          done();
        })
        .request(function(req) {
          req.query = {};
          req.query.code = 'mockcode';
        })
        .authenticate();
    });

    it('should succeeed', function() {
      expect(user).to.deep.equal(mock.getParsedUser());
    });
  });

  describe('handling a return request in which authorization was denied by user', function() {
    var info;
  
    before(function(done) {
      passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        // Simulate Zendesk user denied error
        // https://support.zendesk.com/entries/24458591-Using-OAuth-authentication-with-your-application
        .request(function(req) {
          req.query = {};
          req.query.error = 'access_denied';
          req.query.error_description  = 'The+end-user+or+authorization+server+denied+the+request.';
        })
        .authenticate();
    });
  
    it('should fail with info', function() {
      expect(info).to.not.be.undefined;
      expect(info.message).to.contain('user');
      expect(info.message).to.contain('denied');
    });
  });
});

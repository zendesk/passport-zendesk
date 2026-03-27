const chai = require('chai');
const { expect } = chai;
const ZendeskStrategy = require('..');
const mock = require('./mock');
const { passport } = require('./chai.passport.strategy');

describe('Strategy', function() {

  describe('constructor', function() {
    it('should throw for an invalid subdomain', function() {
      expect(function() {
        new ZendeskStrategy(
          { subdomain: 'evil.com#', clientID: 'id', clientSecret: 'secret' },
          function() {}
        );
      }).to.throw(Error, 'Invalid subdomain');
    });

    it('should set _state from options', function() {
      var s = new ZendeskStrategy(
        { subdomain: mock.subdomain, clientID: 'id', clientSecret: 'secret', state: true },
        function() {}
      );
      expect(s._state).to.equal(true);
    });

    it('should leave _state falsy when not provided', function() {
      var s = new ZendeskStrategy(
        { subdomain: mock.subdomain, clientID: 'id', clientSecret: 'secret' },
        function() {}
      );
      expect(s._state).to.not.be.ok;
    });
  });

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
      expect(location).to.include(mock.authorizationURL);
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

  describe('with state: true', function() {
    var stateStrategy;

    before(function(done) {
      stateStrategy = new ZendeskStrategy(
        { subdomain: mock.subdomain, clientID: 'testclientid', clientSecret: 'testSecret', state: true },
        function(accessToken, refreshToken, profile, done) { done(null, profile); }
      );
      mock.inject(stateStrategy, done);
    });

    describe('authorization redirect', function() {
      var location;
      var session;

      before(function(done) {
        passport.use(stateStrategy)
          .redirect(function(l) { location = l; done(); })
          .request(function(req) {
            req.query = {};
            req.session = {};
            session = req.session;
          })
          .authenticate();
      });

      it('should include a state param in the redirect URL', function() {
        expect(location).to.match(/[?&]state=/);
      });

      it('should store state in session', function() {
        var key = stateStrategy._key;
        expect(session[key]).to.have.property('state');
      });
    });

    describe('callback with mismatched state', function() {
      var failStatus;

      before(function(done) {
        var key = stateStrategy._key;
        passport.use(stateStrategy)
          .fail(function(info, status) { failStatus = status; done(); })
          .request(function(req) {
            req.query = { code: 'mockcode', state: 'wrong-state' };
            req.session = {};
            req.session[key] = { state: 'correct-state' };
          })
          .authenticate();
      });

      it('should fail with 403', function() {
        expect(failStatus).to.equal(403);
      });
    });
  });

  describe('retrieving user profile with an invalid subdomain', function() {
    var profileError;

    before(function(done) {
      strategy.userProfile('mocktoken', 'evil.com#', function(err) {
        profileError = err;
        done();
      });
    });

    it('should error', function() {
      expect(profileError).to.be.an.instanceof(Error);
      expect(profileError.message).to.equal('Invalid subdomain');
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

/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai');
var ZendeskStrategy = require('..');
var fs = require('fs');
var querystring = require('querystring');
var mock = require('./mock');

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

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e){
          err = e;
          done();
        })
        .req(function(req) {
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
      chai.passport.use(strategy)
        .redirect(function(location){
          redirectUrl = location;
          done();
        })
        .req(function(req) {
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
      chai.passport.use(strategy)
        .redirect(function(location){
          redirectUrl = location;
          done();
        })
        .req(function(req) {
          req.session = {};
          req.body = querystring.stringify({subdomain: mock.subdomain});
        })
        .authenticate();
    });

    it('should redirect to correct zendesk subdomain', function() {
      expect(redirectUrl).to.equal(mock.authorizationURL);
    })
  });
});
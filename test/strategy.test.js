/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , SharepointStrategy = require('../lib/passport-sharepoint').Strategy;


describe('Strategy', function() {
    
  describe('constructed', function() {
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret'
      },
      function() {});
    
    it('should be named sharepoint', function() {
      expect(strategy.name).to.equal('sharepoint');
    });
  })

  describe('authorization request without spSite configured', function() {
    var callbackURL = 'htto://foo.com';
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret',
        callbackURL: callbackURL
      }, function() {});
    
    
    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {})
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('InternalOAuthError');
      expect(err.message).to.equal('SharePointStrategy requires a spSiteUrl.');
    });
  });

  describe('authorization request', function() {
    var callbackURL = 'htto://foo.com';
    var spSiteUrl = 'http://www.sharepoint.com';
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret',
        callbackURL: callbackURL,
        spSiteUrl: spSiteUrl
      }, function() {});
    
    
    var url;

    before(function(done) {
      chai.passport.use(strategy)
        .redirect(function(u) {
          url = u;
          done();
        })
        .req(function(req) {
        })
        .authenticate();
    });

    it('should be redirected', function() {
      expect(url).to.equal(spSiteUrl + '/_layouts/15/appredirect.aspx?response_type=code&redirect_uri=htto%3A%2F%2Ffoo.com&client_id=ABC123');
    });
  });

  describe('authorization request with a malformed spAccessToken', function() {
    var callbackURL = 'htto://foo.com';
    var spSiteUrl = 'http://www.sharepoint.com';
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret',
        callbackURL: callbackURL,
        spSiteUrl: spSiteUrl
      }, function() {});
    
    
    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.body = req.body || {};
          req.body.SPAppToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.ImZ1Y2tUaGlzU2hpdCgpOyI.YNr5JV4dPWD6P9fo5s2gO6sNlco1RVMZFrLlLVUiUj0'; 
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('TypeError');
      expect(err.message).to.equal('Cannot read property \'split\' of undefined');
    });
  });

  describe('error caused by token endpoint', function() {
    var callbackURL = 'htto://foo.com';
    var spSiteUrl = 'http://www.sharepoint.com';
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret',
        callbackURL: callbackURL,
        spSiteUrl: spSiteUrl
      }, function() {});
    
    
    var err;

    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.body = req.body || {};
          // Sample token taken from https://blogs.msdn.microsoft.com/kaevans/2013/04/05/inside-sharepoint-2013-oauth-context-tokens/
          req.body.SPAppToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiI0YzJkZjJhYS0zZDE0LTRkODQtOGE3OS01YTc1MTM1ZTk4ZDAvbG9jYWxob3N0OjQ0MzQ2QGQzNDFhNTM2LTFkODItNDI2Ny04N2U2LWUyZGZmZjRmYTMyNSIsImlzcyI6IjAwMDAwMDAxLTAwMDAtMDAwMC1jMDAwLTAwMDAwMDAwMDAwMEBkMzQxYTUzNi0xZDgyLTQyNjctODdlNi1lMmRmZmY0ZmEzMjUiLCJuYmYiOjEzNjUxNzc5NjQsImV4cCI6MTQ5Nzk2NDEwMiwiYXBwY3R4c2VuZGVyIjoiMDAwMDAwMDMtMDAwMC0wZmYxLWNlMDAtMDAwMDAwMDAwMDAwQGQzNDFhNTM2LTFkODItNDI2Ny04N2U2LWUyZGZmZjRmYTMyNSIsImFwcGN0eCI6IntcIkNhY2hlS2V5XCI6XCJlbTEvc2Fab2hUT1M0bk9VWkhYTWI4UUpneU5ia0VPODZUU2U1ajlXWW1vPVwiLFwiU2VjdXJpdHlUb2tlblNlcnZpY2VVcmlcIjpcImh0dHBzOi8vYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldC90b2tlbnMvT0F1dGgvMlwifSIsInJlZnJlc2h0b2tlbiI6IklBQUFBTmM4YkFWTVdaY2VPc2RmZ3NkZmdnYmZtN29VX2FNN0QycW9mVXBRc3RNc2RmZ3NkZmdmWVMwT3RiWi1lWTlVUUd2bFlTbDVrcFBpOTEzRzFBd0lWQk14b0N1eDgtYmhjQ0NpYUdWby12dUZ6clhldGRoUkdQZnRRZEhoLTFyUzVjdkR1dVFfYndfbWp5U0l5dUhOR1NhdkVzOEhVZ0hZOUJPVmMzcFRHWnRaX25TLTFOYkRMWU9iam56bmFzZGZhc2RmYXNkZlFyZUxBZWVPcFZSWTFQR3NkZmdzZGZnT0lUQTNCS2hqSkZ6XzQwWUpNdWJkSG1ZMk9UU25xd05uVWUtckJCQ3Rmdkt0NHhGV3ZkUnpUendmVyIsImlzYnJvd3Nlcmhvc3RlZGFwcCI6InRydWUiLCJqdGkiOiI1OWRhMDQwZi00NmYyLTRkYzEtOTBhYi0xYjFhZjkwNmRiMGQiLCJpYXQiOjE0OTc5NjA1MDJ9.LNMEarfSOn9oSpWBL44QKwbSPMx1CAFhSJ00a72IoNE'; 
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('InternalOAuthError');
      expect(err.message).to.equal('failed to obtain access token');
    });
  });
  
  describe('failure caused by IdP', function() {
    var callbackURL = 'htto://foo.com';
    var spSiteUrl = 'http://www.sharepoint.com';
    var strategy = new SharepointStrategy({
        appId: 'ABC123',
        appSecret: 'secret',
        callbackURL: callbackURL,
        spSiteUrl: spSiteUrl
      }, function() {});
    
    
    var info;
  
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'access_denied';
        })
        .authenticate();
    });
  
    it('should fail with no info', function() {
      expect(info).to.be.undefined;
    });
  });
});
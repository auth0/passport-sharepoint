/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , jwt = require('jwt-simple')
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

  describe('authorization request with a malformed SPAppToken', function() {
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
          req.body.SPAppToken = 'foo';
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('Error');
      expect(err.message).to.equal('Not enough or too many segments');
    });
  });

  describe('authorization request with a SPAppToken with invalid algorithm', function() {
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
      expect(err.constructor.name).to.equal('Error');
      expect(err.message).to.equal('Algorithm not supported');
    });
  });

  describe('authorization request with an invalid SPAppToken signature', function() {
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
      // Sample token taken from https://blogs.msdn.microsoft.com/kaevans/2013/04/05/inside-sharepoint-2013-oauth-context-tokens/
      const sampleToken = {
        "aud": "4c2df2aa-3d14-4d84-8a79-5a75135e98d0/localhost:44346@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "iss": "00000001-0000-0000-c000-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "nbf": 1365177964,
        "exp": 1497964102,
        "appctxsender": "00000003-0000-0ff1-ce00-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "appctx": "{\"CacheKey\":\"em1/saZohTOS4nOUZHXMb8QJgyNbkEO86TSe5j9WYmo=\",\"SecurityTokenServiceUri\":\"https://accounts.accesscontrol.windows.net/tokens/OAuth/2\"}",
        "refreshtoken": "IAAAANc8bAVMWZceOsdfgsdfggbfm7oU_aM7D2qofUpQstMsdfgsdfgfYS0OtbZ-eY9UQGvlYSl5kpPi913G1AwIVBMxoCux8-bhcCCiaGVo-vuFzrXetdhRGPftQdHh-1rS5cvDuuQ_bw_mjySIyuHNGSavEs8HUgHY9BOVc3pTGZtZ_nS-1NbDLYObjnznasdfasdfasdfQreLAeeOpVRY1PGsdfgsdfgOITA3BKhjJFz_40YJMubdHmY2OTSnqwNnUe-rBBCtfvKt4xFWvdRzTzwfW",
        "isbrowserhostedapp": "true",
        "jti": "59da040f-46f2-4dc1-90ab-1b1af906db0d",
        "iat": 1497960502
      };

      const SPAppToken = jwt.encode(sampleToken, 'bad-secret');

      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.body = req.body || {};
          req.body.SPAppToken = SPAppToken;
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('Error');
      expect(err.message).to.equal('Signature verification failed');
    });
  });

  describe('authorization request with an expired SPAppToken', function() {
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
      const sampleToken = {
        "aud": "4c2df2aa-3d14-4d84-8a79-5a75135e98d0/localhost:44346@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "iss": "00000001-0000-0000-c000-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "nbf": 1365177964,
        "exp": 1497964102,
        "appctxsender": "00000003-0000-0ff1-ce00-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "appctx": "{\"CacheKey\":\"em1/saZohTOS4nOUZHXMb8QJgyNbkEO86TSe5j9WYmo=\",\"SecurityTokenServiceUri\":\"https://accounts.accesscontrol.windows.net/tokens/OAuth/2\"}",
        "refreshtoken": "IAAAANc8bAVMWZceOsdfgsdfggbfm7oU_aM7D2qofUpQstMsdfgsdfgfYS0OtbZ-eY9UQGvlYSl5kpPi913G1AwIVBMxoCux8-bhcCCiaGVo-vuFzrXetdhRGPftQdHh-1rS5cvDuuQ_bw_mjySIyuHNGSavEs8HUgHY9BOVc3pTGZtZ_nS-1NbDLYObjnznasdfasdfasdfQreLAeeOpVRY1PGsdfgsdfgOITA3BKhjJFz_40YJMubdHmY2OTSnqwNnUe-rBBCtfvKt4xFWvdRzTzwfW",
        "isbrowserhostedapp": "true",
        "jti": "59da040f-46f2-4dc1-90ab-1b1af906db0d",
        "iat": 1497960502
      };

      const SPAppToken = jwt.encode(sampleToken, 'secret');

      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.body = req.body || {};
          req.body.SPAppToken = SPAppToken;
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err.constructor.name).to.equal('Error');
      expect(err.message).to.equal('Token expired');
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
      const sampleToken = {
        "aud": "4c2df2aa-3d14-4d84-8a79-5a75135e98d0/localhost:44346@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "iss": "00000001-0000-0000-c000-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "nbf": 1365177964,
        "exp": Date.now() + 1000,
        "appctxsender": "00000003-0000-0ff1-ce00-000000000000@d341a536-1d82-4267-87e6-e2dfff4fa325",
        "appctx": "{\"CacheKey\":\"em1/saZohTOS4nOUZHXMb8QJgyNbkEO86TSe5j9WYmo=\",\"SecurityTokenServiceUri\":\"https://accounts.accesscontrol.windows.net/tokens/OAuth/2\"}",
        "refreshtoken": "IAAAANc8bAVMWZceOsdfgsdfggbfm7oU_aM7D2qofUpQstMsdfgsdfgfYS0OtbZ-eY9UQGvlYSl5kpPi913G1AwIVBMxoCux8-bhcCCiaGVo-vuFzrXetdhRGPftQdHh-1rS5cvDuuQ_bw_mjySIyuHNGSavEs8HUgHY9BOVc3pTGZtZ_nS-1NbDLYObjnznasdfasdfasdfQreLAeeOpVRY1PGsdfgsdfgOITA3BKhjJFz_40YJMubdHmY2OTSnqwNnUe-rBBCtfvKt4xFWvdRzTzwfW",
        "isbrowserhostedapp": "true",
        "jti": "59da040f-46f2-4dc1-90ab-1b1af906db0d",
        "iat": 1497960502
      };

      const SPAppToken = jwt.encode(sampleToken, 'secret');

      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.body = req.body || {};
          req.body.SPAppToken = SPAppToken;
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
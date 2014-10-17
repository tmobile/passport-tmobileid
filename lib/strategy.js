/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , qs = require('qs')
  , https = require('https');


/**
 * `Strategy` constructor.
 *
 *  The T-Mobile ID authentication strategy authenticates requests using T-Mobile
 *  ID which closly resembles the Oauth2 framework.
 *
 *  T-Mobile ID first requires you to redirect the user to the Authorization
 *  server to request the user's credentials. When the user successfully logs
 *  in then the server will redirect the authentication code to your previously
 *  verified redirect:
 *
 *      https://localhost:3000/tmoid/callback?code=iz22UVLGClrwzoZyais8
 *
 *  The 'tmoid' strategy retrieves an access token using this 'code' and
 *  provides it to the verify callback along with some additional paramters
 *  for convienience.
 *
 *  Appliations must supply a `verify` callback, for which the function signature
 *  is:
 *
 *      //if passReqToCallback is set to true
 *      function(req, token, expiry, id, done) { ... }
 *      //otherwise
 *      function(token, expiry, id, done) { ... }
 *
 *  The verify callback is responsible for finding or creating the user, and
 *  invoking `done` with the following arguments:
 *
 *      done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 *  Additional `info` can optionally be passed as a third argument, typically
 *  used to display informational messages. If an exception occured, `err`
 *  should be set.
 *
 *  Required Options:
 *
 *  - `redirect_uri` URL to which the service provider will redirect the user after obtaining an authorization code
 *  - `tokenHostname` The server name used to request the token. This is the FQDN of the endpoint without the protocol or path specified (ex. 'token.tmus.net').
 *  - `tokenPath` The server endpoint path; such as '/oauth2/v1/token'
 *  - `clientID` Your T-Mobile provided client ID
 *  - `clientSecret` Your T-Mobile provided client secret
 *  - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 *  Examples:
 *
 *     var TMobileIDStrategy = require('passport-tmoid').Strategy;
 *
 *     passport.use(new TMobileIDStrategy({
 *         redirect_uri : LOCAL_CALLBACK_URL,
 *         tokenHostname : 'token.tmus.net',
 *         tokenPath : '/oauth2/v1/token',
 *         clientID : TMOBILE_CLIENT_ID,
 *         clientSecret : TMOBILE_CLIENT_SECRET,
 *         passReqToCallback : true //to get the req back from passport
 *     },
 *     function(req, token, expiry, id, done){
 *       if(err){return done(err);}
 *       if(!token){return done(null, false);} //No token could be retrieved from the server
 *       if(id) {
 *         //A T-Mobile access token has been provided
 *         User.findOne({'user.tmobileid' : id}, function(err,user){
 *           if(user) //a user with this id has been found in your database
 *             user.tmobile.access_token = token; //add the tmobile access token to this user
 *             user.save(function(err){
 *               //handle the error
 *             }
 *             return done (null, user); //success
 *         });
 *       }
 *     };
 *
 *  @constructor
 *  @param {Object} options
 *  @param {Function} verify
 *  @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('TmoidStrategy requires a verify callback'); }
  if (!options.redirect_uri) { throw new TypeError('TmoidStrategy requires a redirect URI option'); }
  if (!options.tokenHostname) { throw new TypeError('TmoidStrategy requires a token hostname option'); }
  if (!options.tokenPath) { throw new TypeError('TmoidStrategy requires a token path option'); }
  if (!options.clientID) { throw new TypeError('TmoidStrategy requires a clientID option'); }
  if (!options.clientSecret) { throw new TypeError('TmoidStrategy requires a clientSecret option'); }

  passport.Strategy.call(this);
  this.name = 'tmoid';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this._grant_type = options.grant_type || 'authorization_code';
  this._redirect_uri = options.redirect_uri;
  this._tokenHostname = options.tokenHostname;
  this._tokenPath = options.tokenPath;
  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the query code returned in the callback.
 * Ex. https://localhost/tmoid/callback?code=iz22UVLGClrwzoZyais8
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  if (!req.query.code) {
    return this.fail({ message: 'Missing code' }, 400);
  }

  var self = this;

  var query = qs.stringify({
    'grant_type' : this._grant_type,
    'code' : req.query.code,
    'redirect_uri' : this._redirect_uri
  });

  var request_options = {
    hostname: options.tokenHostname ? options.tokenHostname : this._tokenHostname,
    port: 443,
    path: this._tokenPath + '?' + query,
    method: 'POST',
    auth: this._clientID + ':' + this._clientSecret,
    headers : {
      'content-type' : 'application/x-www-form-urlencoded'
    },
    secureProtocol: 'SSLv3_method',
    rejectUnauthorized: false,
    timeout: 3
  };
  request_options.agent = new https.Agent(request_options);

  var https_req = https.request(request_options, function(https_res){
    var data ='';

    https_res.on('data', function (chunk) {
      data += chunk;
    });

    https_res.setEncoding('utf8');

    https_res.on('end', function() {
      var JSON_data = JSON.parse(data);

      if(JSON_data.error){
        self.fail({message: JSON_data.error_description}, 400);
      }

      var token = JSON_data.access_token;
      var token_type = JSON_data.token_type;
      var expiry = JSON_data.expires_in;
      var id = JSON_data.tmobileid;
      var scope = JSON_data.scope;

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {
          self._verify(req, token, expiry, id, verified);
        } else {
          self._verify(token, expiry, id, verified);
        }
      } catch (ex) {
        return self.error(ex);
      }
    });
  });

  https_req.on('error', function(e) {
    self.fail({message: e}, 400);
  });

  https_req.end();
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

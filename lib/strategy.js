/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , url = require('url');


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
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 *  Examples:
 *
 *     var TMobileIDStrategy = require('passport-tmoid').Strategy;
 *
 *     passport.use(new TmoidStrategy({
 *          authorizationURL: TMOBILE_AUTHORIZATION_URL,
 *          tokenURL: TMOBILE_TOKEN_URL,
 *          clientID: TMOBILE_CLIENT_ID,
 *          clientSecret: TMOBILE_CLIENT_SECRET,
 *          callbackURL: LOCAL_CALLBACK_URL,
 *          passReqToCallback : true
 *     },
 *     function(req, token, refreshToken, params, profile, done){
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
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://auth.tmus.net/oauth2/v1/auth';
  options.tokenURL = options.tokenURL || 'https://token.tmus.net/oauth2/v1/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'tmoid';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request based on the query code returned in the callback.
 * Ex. https://localhost/tmoid/callback?code=iz22UVLGClrwzoZyais8
 *
 * @param {Object} req
 * @api protected
 * @options passed to OAuth2Strategy
 */
Strategy.prototype.authenticate = function(req, options) {
  //   FIX: https://github.com/jaredhanson/passport-oauth/issues/16
  if (req.query && req.query.error_code && !req.query.error) {
    return this.error(new CreateError(req.query.error_message, parseInt(req.query.error_code, 10)));
  }

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

Strategy.prototype.authorizationParams = function(options) {
  var params = {};

  // This parameter is not added at default
  params['access_type'] = 'ONLINE';

  return params;
};

/**
 * Creating error handling class
 */

function CreateError(message, code) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'TMobileAuthorizationError';
  this.message = message;
  this.code = code;
  this.status = 500;
}

CreateError.prototype.__proto__ = Error.prototype;


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
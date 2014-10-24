# passport-tmobileid

A [Passport](http://passportjs.org/) strategy for authenticating with [T-Mobile ID](http://www.t-mobile.com/)
using a method similar to OAuth 2.0 API.

This module lets you authenticate using T-Mobile ID in your Node.js applications.
By plugging into Passport, T-Mobile ID authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, like
[Express](http://expressjs.com/).

## Install
```
$ npm install passport-tmobileid
```
## Usage

The T-Mobile ID authentication strategy authenticates users using their phone number or T-Mobile
ID username. Developers wishing to utilize this plugin must first redirect their users to the T-Mobile
authorization endpoint with the appropriate params.
```
var params = {'access_type': 'ONLINE',
  'redirect_uri': 'https://localhost:3000/tmoid/callback',
  'scope': 'TMO_ID_profile,associated_lines,billing_information,entitlements',
  'client_id': TMOBILE_ID_CLIENT,
  'response_type' : 'code'};

res.redirect('https://auth.tmus.net/oauth2/v1/auth?' + qs.stringify(params));
```
#### Configure Strategy

The strategy requires five elements in order to properly process the authentication request, these are:
  1. redirect_uri - The callback URL local to your server
  3. tokenURL - The URL to the token request server
  4. clientID - Your client ID provied by T-Mobile
  5. clientSecret - Your client secret key provided by T-Mobile

```
var TMobileIDStrategy = require('passport-tmoid').Strategy;

passport.use(new TMobileIDStrategy({
    redirect_uri : LOCAL_CALLBACK_URL,
    tokenURL : 'https://token.tmus.net/oauth2/v1/token',
    clientID : TMOBILE_CLIENT_ID,
    clientSecret : TMOBILE_CLIENT_SECRET,
    passReqToCallback : true //to get the req back from passport
},
function(req, token, expiry, id, done){
  if(err){return done(err);}
  if(!token){return done(null, false);} //No token could be retrieved from the server
  if(id) {
    //A T-Mobile access token has been provided
    User.findOne({'user.tmobileid' : id}, function(err,user){
      if(user) //a user with this id has been found in your database
        user.tmobile.access_token = token; //add the tmobile access token to this user
        user.save(function(err){
          //handle the error
        }
        return done (null, user); //success
    });
  }
};  
```
#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'tmoid'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```
app.get('/auth/tmoid',
  res.redirect('https://uat.auth.tmus.net/oauth2/v1/auth?' + qs.stringify(params)));

app.get('/auth/tmoid/callback',
  passport.authenticate('tmoid', {
    failureRedirect: '/login',
    successRedirect: '/profile'
  }),
    function(req, res) {
      // Successful authentication, do nothing.
  });
```

## Examples

For a complete, working example, refer to the [example](https://github.com/tmobile/passport-tmobileid/tree/master/examples).

## Issues

## Related Modules

## Tests - Not implemented yet

    $ npm install
    $ npm test

## Credits

  - [Aaron Drake](https://github.com/drakar)

## License

[T-Mobile Terms and Conditions](https://github.com/tmobile/passport-tmobileid/blob/master/LICENSE)

(c) 2014 T-Mobile USA, Inc. All Rights Reserved.

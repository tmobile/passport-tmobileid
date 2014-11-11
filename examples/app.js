var LOCAL_CALLBACK_URL = "--insert-tmobile-local-callback-url-here--";
var TMOBILE_CLIENT_ID = "--insert-tmobile-client-id-here--";
var TMOBILE_CLIENT_SECRET = "--insert-tmobile-client-secret-here--";

var params = {'access_type': 'ONLINE',
  'redirect_uri': 'https://localhost:3000/tmoid/callback',
  'scope': 'TMO_ID_profile,associated_lines,billing_information,entitlements',
  'client_id': TMOBILE_CLIENT_ID,
  'response_type' : 'code'};

var express = require('express')
    , passport = require('passport')
    , qs = require('qs')
    , TMobileIDStrategy = require('passport-tmoid').Strategy;

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
        return done(null, user); //success
    });
  }
};


var app = express.createServer();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(passport.initialize());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

app.get('/login', function(req, res) {
    res.render('login', { user: req.user });
});

app.get('/profile', function(req, res) {
    res.render('profile', { user: req.user});
});

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

app.listen(3000);

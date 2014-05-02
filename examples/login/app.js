var express = require('express'),
    passport = require('passport'),
    ZendeskStrategy = require('passport-zendesk').Strategy;

var ZENDESK_CLIENT_ID = "your_client_id_here";
var ZENDESK_CLIENT_SECRET = "your_client_secret_here";
var ZENDESK_SUBDOMAIN = "your_zendesk_subdomain_here";

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Zendesk profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

// Use the ZendeskStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Zendesk
//   profile), and invoke a callback with a user object.
passport.use(new ZendeskStrategy({
        subdomain: ZENDESK_SUBDOMAIN,
        clientID: ZENDESK_CLIENT_ID,
        clientSecret: ZENDESK_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/zendesk/callback"
    },
    function(accessToken, refreshToken, profile, done) {
        return done(null, profile);
    }
));

var app = express();

// configure Express
app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'ejs');
    app.use(express.logger());
    app.use(express.cookieParser());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.session({
        secret: 'keyboard cat'
    }));
    // Initialize Passport!  Also use passport.session() middleware, to support
    // persistent login sessions (recommended).
    app.use(passport.initialize());
    app.use(passport.session());
    app.use(app.router);
    app.use(express.static(__dirname + '/public'));
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

app.get('/', function(req, res) {
    res.render('index', {
        user: req.user
    });
});

app.get('/account', ensureAuthenticated, function(req, res) {
    res.render('account', {
        user: req.user
    });
});

app.get('/login', function(req, res) {
    res.render('login', {
        user: req.user
    });
});

app.get('/auth/zendesk',
    passport.authenticate('zendesk'),
    function() {
        // The request will be redirected to Zendesk for authentication, so this
        // function will not be called.
    });

app.get('/auth/zendesk/callback',
    passport.authenticate('zendesk', {
        failureRedirect: '/login'
    }),
    function(req, res) {
        res.redirect('/');
    });

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

app.listen(3000);
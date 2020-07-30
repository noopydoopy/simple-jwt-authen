const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require("body-parser");
const ExtractJwt = require("passport-jwt").ExtractJwt;
const JwtStrategy = require("passport-jwt").Strategy;
const passport = require("passport");
require('dotenv').config();

// AAD passprt config.
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const passportConfig = require('./passportConfig');


const { loginMIddleware } = require('./middleware');
const { response } = require('express');
const secret = process.env.APP_SECRET;
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: secret
};

const jwtAuth = new JwtStrategy(jwtOptions, (payload, done) => {
    // TODO : Apply the logic to verify user.
    if (payload.email === process.env.USERNAME) done(null, true);
    else done(null, false);
});

const ensureAuthenticated = passport.authenticate("jwt", { session: false }, (error, payload) => {
    console.log(error);
});

const verifyToken = (req, res, next) => {
    if (req.headers.authorization) {
        jwt.verify(req.headers.authorization, secret, (error, decoded) => {
            console.log(decoded);
            if (!error)
                return next();
            else
                res.send(401, 'Unauthorized');
        })
    } else {
        res.send(401, 'Unauthorized');
    }
}
// passport.use(jwtAuth); // Apply jwt strategy

const session = require('express-session');
const sessOpts = {
    name: 'umi-session',
    secret: 'session-secret',
    resave: true,
    saveUninitialized: true,
    cookie: { expires: new Date(Date.now() + 86400000), httpOnly: false }
};

const app = express();
app.use(require('cookie-parser')('session-secret'));
app.use(session(sessOpts));
app.use(bodyParser.json()); // Accept json from body
app.use(bodyParser.urlencoded({ extended: true }));

// passport configuration.
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    done(null, user.email);
});

passport.deserializeUser(function (email, done) {
    done(null, email);
});

// declare strategy auth passport
passport.use(new OIDCStrategy({
    identityMetadata: passportConfig.creds.identityMetadata,
    clientID: passportConfig.creds.clientID,
    responseType: passportConfig.creds.responseType,
    responseMode: passportConfig.creds.responseMode,
    redirectUrl: passportConfig.creds.redirectUrl,
    allowHttpForRedirectUrl: passportConfig.creds.allowHttpForRedirectUrl,
    clientSecret: passportConfig.creds.clientSecret,
    validateIssuer: passportConfig.creds.validateIssuer,
    isB2C: passportConfig.creds.isB2C,
    issuer: passportConfig.creds.issuer,
    passReqToCallback: passportConfig.creds.passReqToCallback,
    scope: passportConfig.creds.scope,
    useCookieInsteadOfSession: passportConfig.creds.useCookieInsteadOfSession,
    cookieEncryptionKeys: passportConfig.creds.cookieEncryptionKeys,
    loggingLevel: passportConfig.creds.loggingLevel
},
    function (req, iss, sub, profile, jwtClaims, access_token, refresh_token, params, done) {
        if (!profile.oid) {
            return done(new Error('No oid found'), null);
        }
        // asynchronous verification, for effect...
        process.nextTick(function () {
            return done(null, jwtClaims);
        });
    }
));


app.get("/", verifyToken, (req, res) => {
    res.send("You are in authenticated site.");
});

app.get('/public', (req,res) => {
    response.send('Welcome! you can access this openly.')
})

app.post('/login', loginMIddleware, (req, res) => {
    const claims = {
        name: req.body.username,
        expired_in: new Date(Date.now() + 8640)
    }
    res.send(jwt.encode(claims, secret));
})

app.get('/loginAzure',
    function (req, res, next) {
        passport.authenticate('azuread-openidconnect',
            {
                response: res, // required
                failureRedirect: '/', //the url redirected to when the authentication fails
                customState: 'umi'
            }
        )(req, res, next);
    });

const authenticateAAD = (req, res, next) => {
    try {
        passport.authenticate('azuread-openidconnect', function (err, user) {

            console.log('Get through authenticateAAD');
            if (err) {
                res.locals.err = err;
                return next(err);
            }

            if (!user) {
                res.locals.err = new Error('User does not exist');
                return next();
            }

            console.log('Calling login');

            req.logIn(user, function (err) {
                if (err) {
                    res.locals.err = new Error('User does not exist');
                    return next(err);
                }

                console.log(user);

                req.user = user;
            });
            next();
        })(req, res, next);
    } catch (err) {
        res.locals.err = err;
        next();
    }
};

const authenticateCallback = (req, res) => {
    // todo apply jwt again here.
    if (!res.locals.err) {
        const claims = {
            name: req.user.name,
            email: req.user.email
        }
        const token = jwt.sign(claims, secret, { expiresIn: 60 });
        res.send(token);
    } else {
        res.send(500, res.locals.err.message);
    }

};

app.post('/auth/openid/return', authenticateAAD, authenticateCallback);


app.listen(3000, "", () => console.log('App start listening to port 3000'));
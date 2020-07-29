const express = require('express');
const jwt = require("jwt-simple");
const bodyParser = require("body-parser");
const ExtractJwt = require("passport-jwt").ExtractJwt;
const JwtStrategy = require("passport-jwt").Strategy;
const passport = require("passport");
require('dotenv').config();


const { loginMIddleware } = require('./middleware');
const { response } = require('express');
const secret = process.env.APP_SECRET;
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader("authorization"),
    secretOrKey: secret
};

const jwtAuth = new JwtStrategy(jwtOptions, (payload, done) => {
    if (payload.name === process.env.USERNAME) done(null, true);
    else done(null, false);
});

const ensureAuthenticated = passport.authenticate("jwt", { session: false });

passport.use(jwtAuth); // Apply jwt strategy

const app = express();
app.use(bodyParser.json()); // Accept json from body


app.get("/", ensureAuthenticated, (req, res) => {
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


app.listen(3000, "", () => console.log('App start listening to port 3000'));
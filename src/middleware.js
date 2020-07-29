require('dotenv').config();

const middleware = (req, res, next) => {
    // Check from the authentication logic
    if (req.headers.authorization == "tan") {
        next();
    }
    res.send(401, "Unauthorized.");
};

const loginMIddleware = (req, res, next) => {
    if(req.body.username === process.env.USERNAME && req.body.password === process.env.PASSWORD) {
        next();
    }
    res.send(400, 'Username or password is not correct.')
}

module.exports = {
    middleware,
    loginMIddleware
};
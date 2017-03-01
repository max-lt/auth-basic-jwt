const DEFAULT_RESPONSE = {};
const LOGOUT_RESPONSE = {message: 'goodbye'};
const LOGIN_FAILED_RESPONSE = {message: 'Bad user or Password'};
const UNAUTHORIZED_RESPONSE = {message: 'Unauthorized'};
const EXPIRED_JWT_RESPONSE = {message: 'jwt expired'};
const INVALID_JWT_RESPONSE = {message: 'invalid signature'};

const btoa = (w) => new Buffer(w).toString('base64');
const atob = (w) => new Buffer(w, 'base64').toString();

function commonFactory(auth) {
    const app = require('express')();

    app.use(auth.core);
// Handle Auth errors
    app.use((error, req, res, next) => {
        console.warn(error.message);
        res.status(500).json({
            error: {
                message: 'Auth Error',
                code: 500
            }
        })
    });

    app.get('/admin', auth.admin, (req, res, next) => {
        next();
    });

    app.get('/user', auth.user, (req, res, next) => {
        next();
    });

    app.get('/info', (req, res) => {
        res.status(200).json({user: req.user, authenticated: req.authenticated});
    });

    app.get('*', (req, res) => {
        res.status(200).json(DEFAULT_RESPONSE);
    });

// Handle 500
    app.use((error, req, res, next) => {
        console.warn(error.message);
        res.status(500).json({
            error: {
                message: 'Internal Server Error',
                code: 500
            }
        })
    });

    return {
        app,
        DEFAULT_RESPONSE,
        LOGOUT_RESPONSE,
        LOGIN_FAILED_RESPONSE,
        UNAUTHORIZED_RESPONSE,
        EXPIRED_JWT_RESPONSE,
        INVALID_JWT_RESPONSE,
        btoa,
        atob
    };
}

module.exports = commonFactory;
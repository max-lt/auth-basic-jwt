"use strict";

const request = require('supertest');
const assert = require('assert');

const DEFAULT_USER = {name: 'user', roles: ['user'], pass: 'pass'};
const DEFAULT_ADMIN = {name: 'admin', roles: ['admin'], pass: 'pass'};
const DEFAULT_ANONYMOUS_RESPONSE = {authenticated: false, user: {name: 'anonymous'}};
const DEFAULT_USER_RESPONSE = {authenticated: true, user: {name: 'user', roles: ['user']}};
const DEFAULT_ADMIN_RESPONSE = {authenticated: true, user: {name: 'admin', roles: ['admin']}};
const LOGOUT_RESPONSE = {message: 'goodbye'};
const LOGIN_FAILED_RESPONSE = {message: 'Bad user or Password'};
const UNAUTHORIZED_RESPONSE = {message: 'Unauthorized'};
const EXPIRED_JWT_RESPONSE = {message: 'jwt expired'};
const INVALID_JWT_RESPONSE = {message: 'invalid signature'};
const PROMISE_DELAY = 15;
const ERROR_500_RESPONSE = {error: {message: 'Internal Server Error', code: 500}};
const ERROR_404_RESPONSE = {error: 'Not Found', code: 404};

const hasToken = (res) => {
    if (!('token' in res.body)) throw new Error("missing token key")
};

const makeDefaultUser = (name, pass = 'pass') => ({name, roles: ['user'], pass});

const hasUserMatchingUser = (res, userName) => {
    if (!('user' in res.body)) throw new Error("missing user key");
    if (!('name' in res.body.user)) throw new Error("missing user.name key");
    if (res.body.user.name != userName) throw new Error("user.name value is not userName");
};

const btoa = (w) => new Buffer(w).toString('base64');
const atob = (w) => new Buffer(w, 'base64').toString();

function commonFactory(auth) {
    const app = require('express')();

    app.use(auth.default);

    app.get('/admin', auth.admin, (req, res, next) => {
        next();
    });

    app.get('/user', auth.user, (req, res, next) => {
        next();
    });

    app.get('*', (req, res) => {
        res.status(200).json({user: req.user, authenticated: req.authenticated});
    });

    app.use(auth.unauthorized);

    app.use((req, res, next) => {
        res.status(404).send(ERROR_404_RESPONSE);
    });

// Handle 500
    app.use((error, req, res, next) => {
        res.status(500).json(ERROR_500_RESPONSE)
    });

    return {
        app,
        request,
        assert,
        DEFAULT_ANONYMOUS_RESPONSE,
        DEFAULT_USER_RESPONSE,
        DEFAULT_ADMIN_RESPONSE,
        LOGOUT_RESPONSE,
        LOGIN_FAILED_RESPONSE,
        UNAUTHORIZED_RESPONSE,
        EXPIRED_JWT_RESPONSE,
        INVALID_JWT_RESPONSE,
        PROMISE_DELAY,
        ERROR_500_RESPONSE,
        ERROR_404_RESPONSE,
        hasUserMatchingUser,
        hasToken,
        btoa,
        atob
    };
}

module.exports = commonFactory;
module.exports.makeDefaultUser = makeDefaultUser;
module.exports.DEFAULT_ANONYMOUS_RESPONSE = DEFAULT_ANONYMOUS_RESPONSE;
module.exports.DEFAULT_USER = DEFAULT_USER;
module.exports.DEFAULT_ADMIN = DEFAULT_ADMIN;
module.exports.DEFAULT_USER_RESPONSE = DEFAULT_USER_RESPONSE;
module.exports.DEFAULT_ADMIN_RESPONSE = DEFAULT_ADMIN_RESPONSE;
module.exports.LOGOUT_RESPONSE = LOGOUT_RESPONSE;
module.exports.LOGIN_FAILED_RESPONSE = LOGIN_FAILED_RESPONSE;
module.exports.UNAUTHORIZED_RESPONSE = UNAUTHORIZED_RESPONSE;
module.exports.EXPIRED_JWT_RESPONSE = EXPIRED_JWT_RESPONSE;
module.exports.INVALID_JWT_RESPONSE = INVALID_JWT_RESPONSE;
module.exports.PROMISE_DELAY = PROMISE_DELAY;
module.exports.hasUserMatchingUser = hasUserMatchingUser;
module.exports.hasToken = hasToken;
module.exports.btoa = btoa;
module.exports.atob = atob;
module.exports.request = request;
module.exports.assert = assert;
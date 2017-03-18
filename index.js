"use strict";

const basicAuth = require('basic-auth');
const tokenAuth = require('./bearer-auth');
const jwt = require('jsonwebtoken');
const parseUrl = require('parseurl');
const {promiseOrVar, funcOrVar} = require('./util');

class AuthenticationError extends Error {
    constructor(message) {
        if (message instanceof Error) {
            super(message.message);
            Object.assign(this, message);
        }
        else super(message);
        this.name = 'AuthenticationError';
    }
}

/**
 * @param secret
 * @param userGetter
 * @param options
 * @return {{any: anyLevel, user: userLevel, admin: adminLevel, core: [logout, authBasic, login, authJWT, anyLevel]}}
 */
module.exports = (secret, userGetter, options) => {
    if (!secret) throw new Error("No secret set");
    if (!userGetter) throw new Error("No userGetter set");
    const opts = Object.assign({token: {}, login: {}, password: {}, session: {}}, options);

    function pack(req, res, next) {
        if (req._user) promiseOrVar(funcOrVar(opts.session.filter || defaultFilter, req._user))
            .then((user) => {
                req.user = user;
                delete req._user;
                next();
            });
        else next();
    }

    /** @type {Promise<string|buffer>} */
    let secretPromise = promiseOrVar(secret);

    /** @private */
    function unauthorized(error, req, res, next) {

        if (!(error instanceof AuthenticationError))
            return next(error);

        if (opts.unauthorized) {
            return opts.unauthorized(error, req, res, next);
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
            res.status(401);
            return res.send({message: error.message || 'Unauthorized'});
        }
    }

    function defaultFilter(user) {
        let _u = Object.assign(user);
        delete _u.pass; //hiding user pass in response
        return _u;
    }

    function defaultTokenTransform(token) {
        return token.user || token.iss || null;
    }

    function defaultPassCompare(user, pass) {
        return user.pass === pass;
    }

    function authBasic(req, res, next) {

        //if previous auth succeed
        if (req.authenticated) return next();

        /** @type {{name:string, pass:string}} */
        let basic = basicAuth(req);

        //if basicAuth attempted
        if (basic && basic.name && basic.pass) {
            promiseOrVar(userGetter(basic.name))
                .then((user) => {
                    if (user) {
                        return promiseOrVar(funcOrVar(opts.password.compare || defaultPassCompare, user, basic.pass))
                            .then((validated) => {
                                if (validated) {
                                    req.authenticated = true;
                                    req._user = user;
                                    return next();
                                }
                                else throw new AuthenticationError('Bad user or Password');
                            })
                    }
                    else throw new AuthenticationError('No user match')
                })
                .catch(next);
        }
        else return next();
    }

    function logout(req, res, next) {

        /**@type {{pathname:string}} */
        let url = parseUrl(req);

        if (url.pathname !== '/logout') {
            return next();
        } else {
            req.authenticated = false;
            return res.send({message: 'goodbye'});
        }
    }

    function anyLevel(req, res, next) {
        if (!req.authenticated) {
            req.authenticated = false;
            req.user = {name: 'anonymous'};
        }
        next();
    }

    function userLevel(req, res, next) {
        if (!req.authenticated) next(new AuthenticationError());
        else next();
    }

    function adminLevel(req, res, next) {
        if (!req.authenticated || !req.user.admin) next(new AuthenticationError());
        else next();
    }

    /**
     * Return jwt token if matches /login (POST)
     */
    function login(req, res, next) {

        let url = parseUrl(req);

        if (url.pathname == (opts.login.path || '/login')
            && req.method == (opts.login.method || 'POST')) {
            secretPromise
                .then((secret) => {
                    if (!secret) throw new Error("No secret set");
                    if (req.authenticated) {
                        return promiseOrVar(funcOrVar(opts.token.filter || defaultFilter, req._user))
                            .then((user) => new Promise((resolve, reject) => jwt.sign(Object.assign(
                                {},
                                {user},
                                {
                                    exp: funcOrVar(opts.token.exp, req._user),   // expiration date
                                    iss: funcOrVar(opts.token.iss, req._user),
                                    sub: funcOrVar(opts.token.sub, req._user),   // user id
                                    aud: funcOrVar(opts.token.aud, req._user)   //client id
                                }),
                                secret, {}, (err, token) => {
                                    if (err) {
                                        err.type = 'jwt';
                                        reject(err);
                                    }
                                    else resolve({user, token});
                                })
                            ))
                    }
                    else throw new AuthenticationError('Bad user or Password');
                })
                .then((tokenAndUser) => res.json(tokenAndUser))
                .catch(next);
        }
        else return next();

    }

    function authJWT(req, res, next) {
        //if previous auth succeed
        if (req.authenticated) return next();

        let token = tokenAuth(req);

        //else if JWT auth attempted
        if (token) secretPromise
            .then((secret) => {
                if (!secret) throw new Error("No secret set");
                // for errors see:
                // https://github.com/auth0/node-jsonwebtoken#jsonwebtokenerror
                // https://github.com/auth0/node-jsonwebtoken#tokenexpirederror
                return new Promise((resolve, reject) => {
                    jwt.verify(token, secret, (err, decoded) => {
                        if (err) reject(err);
                        else resolve(decoded)
                    });
                })
            })
            .catch((err) => {
                throw new AuthenticationError(err || 'jwt error');
            })
            .then((decoded) => promiseOrVar(funcOrVar(opts.token.decode || defaultTokenTransform, decoded)))
            .then((user) => {
                req.authenticated = true;
                req.user = user;
                next();
            })
            .catch(next);
        else next();
    }

    return {
        any: anyLevel,
        user: userLevel,
        admin: adminLevel,
        unauthorized: unauthorized,
        core: [logout, authBasic, login, pack, authJWT, anyLevel]
    };
};

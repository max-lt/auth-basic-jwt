"use strict";

const basicAuth = require('basic-auth');
const tokenAuth = require('./bearer-auth');
const jwt = require('jsonwebtoken');
const parseUrl = require('parseurl');
const {promiseOrVar, funcOrVar} = require('./util');
const AuthenticationError = require('./error/AuthenticationError');
const filters = require('./filters');

/**
 * @param secret
 * @param userGetter
 * @param options
 * @return {{any: anyLevel, user: userLevel, admin: adminLevel, default: [logout, authBasic, login, authJWT, anyLevel]}}
 */
module.exports = (secret, userGetter, options) => {
    if (!secret) throw new Error("No secret set");
    if (!userGetter) throw new Error("No userGetter set");
    const opts = Object.assign({token: {}, login: {}, password: {}, session: {}}, options);

    /** @type {Promise<string|buffer>} */
    let secretPromise = promiseOrVar(secret);

    function defaultFilter(user) {
        let u = Object.assign({}, user);
        delete u.pass; // Hiding user pass in response
        return u;
    }

    function defaultTokenTransform(token) {
        return token.user || token.iss || null;
    }

    function defaultPassCompare(user, pass) {
        return user.pass === pass;
    }

    function getUser(user) {
        if (user)
            return promiseOrVar(funcOrVar(opts.session.filter || defaultFilter, user))
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
                                if (validated)
                                    return getUser(user);
                                else
                                    throw new AuthenticationError('Bad user or Password');
                            })
                            .then((user) => {
                                req.authenticated = true;
                                req.user = user;
                                return next();
                            })
                    }
                    else throw new AuthenticationError('No user match')
                })
                .catch(next);
        }
        else return next();
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
                        return promiseOrVar(funcOrVar(opts.token.filter || defaultFilter, req.user))
                            .then((user) => new Promise((resolve, reject) => jwt.sign(Object.assign(
                                {},
                                {user},
                                {
                                    exp: funcOrVar(opts.token.exp, req.user),   // expiration date
                                    iss: funcOrVar(opts.token.iss, req.user),
                                    sub: funcOrVar(opts.token.sub, req.user),   // user id
                                    aud: funcOrVar(opts.token.aud, req.user)   //client id
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

    const defaultFiltersSequence = [filters.logout, authBasic, login, authJWT, filters.anyLevel];

    return {
        any: filters.anyLevel,
        user: filters.userLevel,
        admin: filters.adminLevel,
        unauthorized: filters.unauthorized,
        /** @deprecated */
        get core() {
            console.warn('auth.core is deprecated, use auth.default instead');
            return defaultFiltersSequence;
        },
        default: defaultFiltersSequence
    };
};

"use strict";

const basicAuth = require('basic-auth');
const tokenAuth = require('./bearer-auth');
const jwt = require('jsonwebtoken');
const parseUrl = require('parseurl');
const {promisify, funcOrVar} = require('./util');

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

    /** @type {Promise<string|buffer>} */
    let secretPromise = promisify(secret);

    /** @private */
    function unauthorized(req, res, next, message = 'Unauthorized') {
        if (opts.unauthorized) {
            return opts.unauthorized(req, res, next, message);
        } else {
            res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
            res.status(401);
            return res.send({message: message});
        }
    }

    function defaultFilter(user) {
        let _u = Object.assign(user);
        delete _u.pass; //hiding user pass in response
        return _u;
    }

    function authBasic(req, res, next) {

        //if previous auth succeed
        if (req.authenticated) return next();

        /** @type {{name:string, pass:string}} */
        let basic = basicAuth(req);

        //if basicAuth attempted
        if (basic && basic.name && basic.pass) {
            promisify(userGetter(basic.name)).then((user) => {
                if (user && basic.pass === user.pass) {
                    req.authenticated = true;
                    req.user = funcOrVar(opts.session.filter || defaultFilter, user);
                    return next();
                } else {
                    req.authenticated = false;
                    return unauthorized(req, res, next, 'Bad user or Password');
                }
            }).catch((error) => {
                return unauthorized(req, res, next, 'Bad user or Password');
            });
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
        if (!req.authenticated) unauthorized(req, res, next);
        else next();
    }

    function adminLevel(req, res, next) {
        if (!req.authenticated || !req.user.admin) unauthorized(req, res, next);
        else next();
    }

    /**
     * Return jwt token if matches /login (POST)
     */
    function login(req, res, next) {

        let url = parseUrl(req);

        if (url.pathname == (opts.login.path || '/login')
            && req.method == (opts.login.method || 'POST')) {
            secretPromise.then((secret) => {
                if (!secret) throw new Error("No secret set");
                if (req.authenticated) {
                    const user = funcOrVar(opts.token.filter || defaultFilter, req.user);
                    jwt.sign(Object.assign(
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
                                return next(err);
                            }
                            return res.json({user, token})
                        })
                }
                else return unauthorized(req, res, next, 'Bad user or Password');
            }).catch(next);
        }
        else return next();

    }

    function authJWT(req, res, next) {
        //if previous auth succeed
        if (req.authenticated) return next();

        let token = tokenAuth(req);

        //else if JWT auth attempted
        if (token) {
            secretPromise.then((secret) => {
                if (!secret) throw new Error("No secret set");
                // for errors see:
                // https://github.com/auth0/node-jsonwebtoken#jsonwebtokenerror
                // https://github.com/auth0/node-jsonwebtoken#tokenexpirederror
                jwt.verify(token, secret, function (err, decoded) {
                    if (err) return unauthorized(req, res, next, err.message || 'jwt error');
                    else {
                        req.authenticated = true;
                        req.user = decoded.user;
                    }
                    return next();
                });
            }).catch(next);
        }
        else return next();
    }

    return {
        any: anyLevel,
        user: userLevel,
        admin: adminLevel,
        core: [logout, authBasic, login, authJWT, anyLevel]
    };
};

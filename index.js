/**
 * Created by max on 26/01/17.
 */

"use strict";

const basicAuth = require('basic-auth');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')();
const parseUrl = require('parseurl');

function unauthorized(res, message = 'Unauthorized') {
    res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
    res.status(401);
    return res.send({message: message});
}

function logout(req, res, next) {

    let url = parseUrl(req);

    if (url.pathname !== '/logout') {
        return next();
    } else {
        res.clearCookie('token');
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
    if (!req.authenticated) return unauthorized(res);
    else next();
}

function adminLevel(req, res, next) {
    if (!req.authenticated || !req.user.admin) return unauthorized(res);
    else next();
}

/**
 * @param secret
 * @param userInterface
 * @return {{any: anyLevel, user: userLevel, admin: adminLevel, core: [*,*,*,*,*]}}
 */
module.exports = (secret, userInterface) => {
    if (!secret) throw new Error("No secret set");
    if (!userInterface) throw new Error("No userInterface set");

    function authBasic(req, res, next) {

        //if previous auth succeed
        if (req.authenticated) return next();

        let basic = basicAuth(req);

        //if basicAuth attempted
        if (basic && basic.name && basic.pass) {

            let user = userInterface.get(basic.name);
            if (user && basic.pass === user.pass) {
                req.authenticated = true;
                delete user.pass; //hiding user pass in response
                req.user = user;
                jwt.sign({user: user}, secret, {}, (err, token) => {
                    if (err) throw err;
                    res.cookie('token', token, {
                        maxAge: 3600000, // 1h
                        httpOnly: true
                    });
                    next();
                })
            } else {
                req.authenticated = false;
                res.clearCookie('token');
                return next();
            }
        }
        else return next();
    }

    function authJWT(req, res, next) {
        //if previous auth succeed
        if (req.authenticated) return next();

        //else if JWT auth attempted
        if (req.cookies.token) {
            jwt.verify(req.cookies.token, secret, function (err, decoded) {
                if (err) throw err;
                else {
                    req.authenticated = true;
                    req.user = decoded.user;
                }
                return next();
            });
        }
        else return next();
    }

    return {
        any: anyLevel,
        user: userLevel,
        admin: adminLevel,
        core: [cookieParser, logout, authBasic, authJWT, anyLevel]
    };
};

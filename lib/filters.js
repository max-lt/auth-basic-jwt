const AuthenticationError = require('./error/AuthenticationError');
const parseUrl = require('parseurl');

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

function hasRole(role) {

    if (typeof role !== 'string')
        throw new Error('role must be a string');

    return function (req, res, next) {

        if (!req.authenticated
            || !req.user
            || !req.user.roles
            || !req.user.roles.includes(role))
            return next(new AuthenticationError());

        next();
    }
}

function userLevel(req, res, next) {
    return hasRole('user')(req, res, next)
}

function adminLevel(req, res, next) {
    return hasRole('admin')(req, res, next)
}

function unauthorized(error, req, res, next) {

    if (!(error instanceof AuthenticationError))
        return next(error);

    res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
    res.status(401);
    return res.send({message: error.message || 'Unauthorized'});
}

module.exports = {logout, anyLevel, userLevel, adminLevel, unauthorized, hasRole};
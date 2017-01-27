'use strict';

/**
 * RegExp for Bearer auth token
 *
 * auth-scheme = "Bearer" ; case insensitive
 * @private
 */

const CREDENTIALS_REGEXP = /^ *(?:bearer) +([a-zA-Z0-9\-._]+) *$/i;

/**
 * Get the Authorization header from request object.
 * @private
 */

function getAuthorization (req) {
    return req.get("authorization");
}

/**
 * Parse basic auth to object.
 *
 * @param {string} string
 * @return {object}
 * @public
 */

function parse (string) {
    if (typeof string !== 'string') {
        return undefined
    }

    // parse header
    let match = CREDENTIALS_REGEXP.exec(string);

    if (!match) {
        return undefined
    }

    // return token
    return match[1];
}

/**
 * Parse the Authorization header field of a request.
 *
 * @param {object} req
 * @return {object} with .name and .pass
 * @public
 */

function auth (req) {
    if (!req) {
        throw new TypeError('argument req is required')
    }

    if (typeof req !== 'object') {
        throw new TypeError('argument req is required to be an object')
    }

    // get header
    let header = getAuthorization(req.req || req);

    // parse header
    return parse(header)
}

module.exports = auth;
module.exports.parse = parse;
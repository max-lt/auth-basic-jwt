"use strict";

/**
 * @param {function|*} arg
 * @param {...object} args
 * @return {object}
 * @private
 */
function funcOrVar(arg, ...args) {
    if (typeof arg == 'function') {
        return arg.apply(null, args);
    } else {
        return arg;
    }
}

/**
 * @param {Promise|*} arg
 * @return {Promise}
 * @private
 */
function promiseOrVar(arg) {
    if (arg instanceof Promise) {
        return arg;
    } else {
        return Promise.resolve(arg);
    }
}

module.exports = {promiseOrVar, funcOrVar};
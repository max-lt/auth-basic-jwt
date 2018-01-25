"use strict";

const common = require('./common');
const {DEFAULT_ADMIN, makeDefaultUser, PROMISE_DELAY} = require('./common');
const makeTests = require('./factory');

function userGetter(userName) {
    return new Promise(resolve => {
        setTimeout(() => {
            resolve(userName == 'admin' ? DEFAULT_ADMIN : makeDefaultUser(userName))
        }, PROMISE_DELAY)
    })
}

function getTokenAsync() {
    return new Promise(resolve => {
        setTimeout(() => resolve('SECRET'), PROMISE_DELAY)
    })
}

const auth = require('..')(
    getTokenAsync(),
    userGetter,
    {token: {exp: (user) => Math.floor(Date.now() / 1000) + (60 * 60)}}
);

describe('promises', () => makeTests(auth));
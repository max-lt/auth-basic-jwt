"use strict";

const common = require('./common');
const makeTests = require('./factory');

const PROMISE_DELAY = common.PROMISE_DELAY;

const auth = require('..')(
    getTokenAsync(),
    userGetter,
    {token: {exp: (user) => Math.floor(Date.now() / 1000) + (60 * 60)}}
);

function userGetter(userName) {
    return new Promise(resolve => {
        setTimeout(() => {
            resolve(userName == 'admin' ? {
                    name: 'admin',
                    pass: 'pass',
                    admin: true
                } : {
                    name: userName,
                    pass: 'pass'
                })
        }, PROMISE_DELAY)
    })
}

function getTokenAsync() {
    return new Promise(resolve => {
        setTimeout(() => resolve('SECRET'), PROMISE_DELAY)
    })
}

makeTests('promises', common(auth));
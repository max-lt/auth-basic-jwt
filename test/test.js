"use strict";

const common = require('./common');
const makeTests = require('./factory');


const userGetter = (userName) => (userName == 'admin' ? {
        name: 'admin',
        pass: 'pass',
        admin: true
    } : {
        name: userName,
        pass: 'pass'
    });


const auth = require('..')('SECRET', userGetter, {token: {exp: Math.floor(Date.now() / 1000) + (60 * 60)}});

makeTests('simple', common(auth));
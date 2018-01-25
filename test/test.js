"use strict";

const {DEFAULT_ADMIN, makeDefaultUser} = require('./common');
const makeTests = require('./factory');

const userGetter = (userName) => userName == 'admin' ? DEFAULT_ADMIN : makeDefaultUser(userName);

const auth = require('..')('SECRET', userGetter, {token: {exp: Math.floor(Date.now() / 1000) + (60 * 60)}});

describe('simple', () => makeTests(auth));
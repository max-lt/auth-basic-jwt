"use strict";

const bearerAuth = require('../bearer-auth');

const assert = require('assert');

describe('bearer-auth tests', () => {

    it('auth without parameter should throw Error', () => {
        assert.throws(bearerAuth, TypeError)
    });

    it('auth with invalid parameter should throw Error', () => {
        const test = () => bearerAuth('invalid parameter');
        assert.throws(test, TypeError)
    });

    it('auth with invalid object parameter should throw Error', () => {
        const test = () => bearerAuth({});
        assert.throws(test, TypeError)
    });

    it('auth with invalid getter return type should return nothing', () => {
        const test = bearerAuth({get:()=>({})});
        assert.equal(test, undefined)
    });

    it('auth with invalid getter return should return nothing', () => {
        const test = bearerAuth({get:()=>'invalid return'});
        assert.equal(test, undefined)
    });

    it('auth with invalid getter return should return nothing', () => {
        const test = bearerAuth({get:()=>'invalid return'});
        assert.equal(test, undefined)
    });

    it('auth with invalid getter return should return nothing (2)', () => {
        const test = bearerAuth({get:()=>'bearer invalid return'});
        assert.equal(test, undefined)
    });

    it('auth with matching scheme should return second part', () => {
        const token = 'test';
        const test = bearerAuth({get:()=>'bearer ' + token});
        assert.equal(test, token)
    });

    it('auth with matching scheme beginning with extra space should return second part', () => {
        const token = 'test';
        const test = bearerAuth({get:()=>'   bearer ' + token});
        assert.equal(test, token)
    });

    it('auth with matching scheme ending with extra space should return second part', () => {
        const token = 'test';
        const test = bearerAuth({get:()=>'bearer ' + token + '  '});
        assert.equal(test, token)
    });

    it('auth with matching scheme ending and beginning with extra space should return second part', () => {
        const token = 'test';
        const test = bearerAuth({get:()=>'  bearer ' + token + '  '});
        assert.equal(test, token)
    });

    it('auth with matching scheme with extra space should return second part', () => {
        const token = 'test';
        const test = bearerAuth({get:()=>'  bearer   ' + token + '  '});
        assert.equal(test, token)
    });

});
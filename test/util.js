"use strict";

const {promisify, funcOrVar} = require('../util');

const assert = require('assert');

const PROMISE_DELAY = 5;

describe('util tests: promisify', () => {

    it('should return a promise witch resolve a common parameter', (done) => {
        const data = 3;
        const test = promisify(data);

        assert(test instanceof Promise);

        test.then((resolved) => {
            assert.equal(resolved, data);
            done();
        })
    });

    it('should return a promise witch resolve an immediate promise parameter', (done) => {
        const data = 3;
        const test = promisify(Promise.resolve(data));

        assert(test instanceof Promise);

        test.then((resolved) => {
            assert.equal(resolved, data);
            done();
        })
    });

    it('should return a promise witch resolve a delayed promise parameter', (done) => {
        const data = 3;
        const test = promisify(new Promise(r => setTimeout(_ => r(data), PROMISE_DELAY)));

        assert(test instanceof Promise);

        test.then((resolved) => {
            assert.equal(resolved, data);
            done();
        })
    });

});


describe('util tests: funcOrVar', () => {

    it('should return an object when a getter is passed', () => {
        const data = 3;
        const test = funcOrVar(() => data);
        assert.equal(data, test);
    });

    it('should return an object when a object is passed', () => {
        const data = 3;
        const test = funcOrVar(data);
        assert.equal(data, test);
    });

    it('should care about parameter when a getter is passed', () => {
        const data = 3;
        const test = funcOrVar((multiplier) => data * multiplier, data);
        assert.equal(data * data, test);
    });

    it('should care about parameters when a getter is passed', () => {
        const test = funcOrVar((...args) => args.reduce((a, b) => a + b), 1, 1, 1, 1, 1);
        assert.equal(5, test);
    });

    it('should care about parameters when a getter is passed (2)', () => {
        const test = funcOrVar((a, b, c) => a + b + c, 1, 1, 1);
        assert.equal(3, test);
    });

});
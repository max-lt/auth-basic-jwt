"use strict";

const common = require('./common');
const assert = require('assert');
const request = require('supertest');

const PROMISE_DELAY = require('./common').PROMISE_DELAY;

const auth = require('..')(
    getTokenAsync(),
    userGetter,
    {token: {exp: (user) => Math.floor(Date.now() / 1000) + (60 * 60)}}
);

const {
    app,
    DEFAULT_RESPONSE,
    LOGOUT_RESPONSE,
    LOGIN_FAILED_RESPONSE,
    UNAUTHORIZED_RESPONSE,
    EXPIRED_JWT_RESPONSE,
    INVALID_JWT_RESPONSE,
    hasToken,
    hasUserMatchingUser,
    btoa
} = common(auth);

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

describe('promises: basic auth', () => {

    it('should fail on unprotected if wrong basicAuth attempted', (done) => {
        request(app)
            .get('/')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (get) if wrong basicAuth attempted', (done) => {
        request(app)
            .get('/login')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (post) if wrong basicAuth attempted', (done) => {
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on unprotected (post) if wrong basicAuth attempted', (done) => {
        request(app)
            .post('/any')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on unprotected (delete) if wrong basicAuth attempted', (done) => {
        request(app)
            .delete('/any')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on user if wrong basicAuth attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on admin if wrong basicAuth attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on admin if wrong basicAuth attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('admin:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should be ok on unprotected (get) if good basicAuth (regular user) attempted', (done) => {
        request(app)
            .get('/any')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on user (get) if good basicAuth (regular user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on admin (get) if good basicAuth (regular user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should fail on admin (post) if good basicAuth (regular user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should be ok on admin (get) if good basicAuth (admin user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on /login (get) if good basicAuth (regular user) attempted, but no token expected', (done) => {
        request(app)
            .get('/login')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should return token on /login (post) if good basicAuth (regular user) attempted', (done) => {
        const userName = 'geFDfeghHHx_156';
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa(userName + ':pass'))
            .expect(200)
            .expect(hasToken)
            .expect((res) => hasUserMatchingUser(res, userName))
            .end(done);
    });

    it('should return token on /login (post) if good basicAuth (admin user) attempted', (done) => {
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200)
            .expect(hasToken)
            .expect((res) => hasUserMatchingUser(res, 'admin'))
            .end(done);
    });

    it('should has authenticated user on /info (get) if good basicAuth (regular user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, {user: {name: 'user'}, authenticated: true}, done)
    });

    it('should has authenticated admin on /info (get) if good basicAuth (admin user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200, {user: {name: 'admin', admin: true}, authenticated: true}, done)
    });
});


describe('promises: token auth', () => {

    const token = {
        old: {
            user: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJ1c2VyIn0sImV4cCI6MTQwNTYwNjMwNywiaWF0IjoxNDA1NjAyNzA4fQ.v0cRRQIe7a1jCRZksbjLKuG-Pi7Kx-HkE3QsbrnA_GU',
            admin: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJhZG1pbiIsImFkbWluIjp0cnVlfSwiZXhwIjoxNDA1NjA2MzA3LCJpYXQiOjE0MDU2MDI3MDh9.o0ZZy2K9a1G3DbyaLi9jELCW-sC4cDDN8CT9ocfFCuE'
        },
        bad: {
            user: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJ1c2VyIn0sImlhdCI6MTQ4NTYwNTczMn0.Br3baPKovEyVNDkROERIJnPI3ruYitGzWrH3Q9M6qqQ',
            admin: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJhZG1pbiIsImFkbWluIjp0cnVlfSwiaWF0IjoxNDg1NjA1NzMyfQ.UgIyr73Z_D66GTWz4rTCwSNx6bcsjOxz25QSQ5nD0UA'
        },
        broken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXJ9.eyJ1c2VyIjp7Im5hbWUiOiJhZG1pbiIsImFkbWluIjp0cnVlfSwiaWF0IjoxNDg1NjA1NzMyfQ.UgIyr73Z_D66GTWz4rTCwSNx6bcsjOxz25QSQ5nD0UA'
    };

    before((done) => {

        let _ready = -1;

        function ready() {
            if (++_ready) done();
        }

        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .end((err, res) => {
                token.user = res.body.token;
                ready();
            });

        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .end((err, res) => {
                token.admin = res.body.token;
                ready();
            });

    });

    it('should be ok on * if good tokenAuth (regular user) attempted', (done) => {
        if (!token.user) throw new Error('Not ready');
        request(app)
            .get('/any')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on /user if good tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on /admin if good tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should be ok on /admin if good tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on /login (post) if good tokenAuth (regular user) attempted', (done) => {
        request(app)
            .post('/login')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (post) if good tokenAuth (admin user) attempted', (done) => {
        request(app)
            .post('/login')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should has authenticated user on /info (get) if good tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, {user: {name: 'user'}, authenticated: true}, done)
    });

    it('should has authenticated admin on /info (get) if good tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, {user: {name: 'admin', admin: true}, authenticated: true}, done)
    });

    it('should fail on /user if expired tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.old.user)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.old.admin)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.old.admin)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.old.user)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.bad.user)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.bad.admin)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.bad.admin)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.bad.user)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });
});

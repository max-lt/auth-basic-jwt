"use strict";

const common = require('./common');
const request = require('supertest');
const assert = require('assert');

const userGetter = (userName) => (userName == 'admin' ? {
        name: 'admin',
        pass: 'pass',
        admin: true
    } : {
        name: userName,
        pass: 'pass'
    });

const DEFAULT_USER_SESSION_RESPONSE = {user: {name: 'user', pass: 'pass', sessionfilter: true}, authenticated: true};
const DEFAULT_ADMIN_SESSION_RESPONSE = {
    user: {name: 'admin', admin: true, pass: 'pass', sessionfilter: true},
    authenticated: true
};
const DEFAULT_ADMIN_TOKEN_DECODED_RESPONSE = {admin: true, name: 'admin', tokenDecoded: true};
const DEFAULT_USER_TOKEN_DECODED_RESPONSE = {name: 'user', tokenDecoded: true};

const auth = require('..')('SECRET', userGetter, {
    session: {
        filter: (user) => {
            assert(user.pass)
            console.error('session.filter', user);
            user.sessionfilter = true;
            return user;
        }
    },
    token: {
        filter: (user) => {
            assert(user.pass)
        },
        decode: (token) => token.iss[0] == 'a' ? DEFAULT_ADMIN_TOKEN_DECODED_RESPONSE : DEFAULT_USER_TOKEN_DECODED_RESPONSE,
        iss: (user) => (user.admin ? 'a' : 'u') + '123456',
        exp: Math.floor(Date.now() / 1000) + (60 * 60)
    }
});

const {
    app,
    DEFAULT_USER_RESPONSE,
    DEFAULT_ANONYMOUS_RESPONSE,
    DEFAULT_ADMIN_RESPONSE,
    hasToken,
    btoa
} = common(auth);

describe('token.filter: basic auth', () => {

    it('should return token on /login (post) if good basicAuth (regular user) attempted', (done) => {
        const userName = 'geFDfeghHHx_156';
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa(userName + ':pass'))
            .expect(200)
            .expect(hasToken)
            .end(done);
    });

    it('should return token on /login (post) if good basicAuth (admin user) attempted', (done) => {
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200)
            .expect(hasToken)
            .end(done);
    });

    it('should be ok on /any (get) if good basicAuth (regular user) attempted, but no token expected', (done) => {
        request(app)
            .get('/any')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_USER_SESSION_RESPONSE, done)
    });

    it('should be ok on /any (get) if good basicAuth (regular user) attempted, but no token expected', (done) => {
        request(app)
            .get('/any')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200, DEFAULT_ADMIN_SESSION_RESPONSE, done)
    });


});


describe('token.filter: token auth', () => {

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

    it('should be ok on /admin if good tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, {authenticated: true, user: DEFAULT_ADMIN_TOKEN_DECODED_RESPONSE}, done)
    });

    it('should has authenticated user on /info (get) if good tokenAuth (regular user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, {authenticated: true, user: DEFAULT_USER_TOKEN_DECODED_RESPONSE}, done)
    });

    it('should has authenticated admin on /info (get) if good tokenAuth (admin user) attempted', (done) => {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, {authenticated: true, user: DEFAULT_ADMIN_TOKEN_DECODED_RESPONSE}, done)
    });

});
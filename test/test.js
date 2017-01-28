const assert = require('assert');
const auth = require('..')('SECRET', {
    get: (userName) => (userName == 'admin' ? {
            name: 'admin',
            pass: 'pass',
            admin: true
        } : {
            name: userName,
            pass: 'pass'
        })
}, {token: {exp: Math.floor(Date.now() / 1000) + (60 * 60)}});

const request = require('supertest');
const app = require('express')();

const btoa = (w) => new Buffer(w).toString('base64');
const atob = (w) => new Buffer(w, 'base64').toString();

const DEFAULT_RESPONSE = {};
const LOGOUT_RESPONSE = {message: 'goodbye'};
const LOGIN_FAILED_RESPONSE = {message: 'Bad user or Password'};
const UNAUTHORIZED_RESPONSE = {message: 'Unauthorized'};
const EXPIRED_JWT_RESPONSE = {message: 'jwt expired'};
const INVALID_JWT_RESPONSE = {message: 'invalid signature'};

app.use(auth.core);
// Handle Auth errors
app.use((error, req, res, next) => {
    console.warn(error.message);
    res.status(500).json({
        error: {
            message: 'Auth Error',
            code: 500
        }
    })
});


app.get('/admin', auth.admin, function (req, res, next) {
    next();
});

app.get('/user', auth.user, function (req, res, next) {
    next();
});

app.get('/info', function (req, res) {
    res.status(200).json({user: req.user, authenticated: req.authenticated});
});

app.get('*', function (req, res) {
    res.status(200).json(DEFAULT_RESPONSE);
});

// Handle 500
app.use((error, req, res, next) => {
    console.warn(error.message);
    res.status(500).json({
        error: {
            message: 'Internal Server Error',
            code: 500
        }
    })
});

describe('when no token are sent', function () {
    it('should be ok if not protected', function (done) {
        request(app)
            .get('/')
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on /login (get)', function (done) {
        request(app)
            .get('/login')
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail (401) on /login (post)', function (done) {
        request(app)
            .post('/login')
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should logout on /logout (post)', function (done) {
        request(app)
            .post('/logout')
            .expect(200, LOGOUT_RESPONSE, done)
    });

    it('should logout on /logout (get)', function (done) {
        request(app)
            .get('/logout')
            .expect(200, LOGOUT_RESPONSE, done)
    });

    it('should logout on /logout (delete)', function (done) {
        request(app)
            .delete('/logout')
            .expect(200, LOGOUT_RESPONSE, done)
    });

    it('should has anonymous user on /info (get)', function (done) {
        request(app)
            .get('/info')
            .expect(200, {user: {name: 'anonymous'}, authenticated: false}, done)
    });
});

describe('basic auth', function () {

    const hasToken = (res) => {
        if (!('token' in res.body)) throw new Error("missing token key")
    };

    const hasUserMatchingUser = (res, userName) => {
        if (!('user' in res.body)) throw new Error("missing user key");
        if (!('name' in res.body.user)) throw new Error("missing user.name key");
        if (res.body.user.name != userName) throw new Error("user.name value is not userName");
    };

    it('should fail on unprotected if wrong basicAuth attempted', function (done) {
        request(app)
            .get('/')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (get) if wrong basicAuth attempted', function (done) {
        request(app)
            .get('/login')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (post) if wrong basicAuth attempted', function (done) {
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on unprotected (post) if wrong basicAuth attempted', function (done) {
        request(app)
            .post('/any')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on unprotected (delete) if wrong basicAuth attempted', function (done) {
        request(app)
            .delete('/any')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on user if wrong basicAuth attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on admin if wrong basicAuth attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on admin if wrong basicAuth attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('admin:wrongPass'))
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should be ok on unprotected (get) if good basicAuth (regular user) attempted', function (done) {
        request(app)
            .get('/any')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on user (get) if good basicAuth (regular user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on admin (get) if good basicAuth (regular user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should fail on admin (post) if good basicAuth (regular user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should be ok on admin (get) if good basicAuth (admin user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on /login (get) if good basicAuth (regular user) attempted, but no token expected', function (done) {
        request(app)
            .get('/login')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should return token on /login (post) if good basicAuth (regular user) attempted', function (done) {
        let userName = 'geFDfeghHHx_156';
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa(userName + ':pass'))
            .expect(200)
            .expect(hasToken)
            .expect((res) => hasUserMatchingUser(res, userName))
            .end(done);
    });

    it('should return token on /login (post) if good basicAuth (admin user) attempted', function (done) {
        request(app)
            .post('/login')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200)
            .expect(hasToken)
            .expect((res) => hasUserMatchingUser(res, 'admin'))
            .end(done);
    });

    it('should has authenticated user on /info (get) if good basicAuth (regular user) attempted', function (done) {
        request(app)
            .get('/info')
            .set('Authorization', 'Basic ' + btoa('user:pass'))
            .expect(200, {user: {name: 'user'}, authenticated: true}, done)
    });

    it('should has authenticated admin on /info (get) if good basicAuth (admin user) attempted', function (done) {
        request(app)
            .get('/info')
            .set('Authorization', 'Basic ' + btoa('admin:pass'))
            .expect(200, {user: {name: 'admin', admin: true}, authenticated: true}, done)
    });
});


describe('token auth', function () {

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

    request(app)
        .post('/login')
        .set('Authorization', 'Basic ' + btoa('user:pass'))
        .end(function (err, res) {
            token.user = res.body.token;
        });

    request(app)
        .post('/login')
        .set('Authorization', 'Basic ' + btoa('admin:pass'))
        .end(function (err, res) {
            token.admin = res.body.token;
        });


    it('should be ok on * if good tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/any')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should be ok on /user if good tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on /admin if good tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(401, UNAUTHORIZED_RESPONSE, done)
    });

    it('should be ok on /admin if good tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, DEFAULT_RESPONSE, done)
    });

    it('should fail on /login (post) if good tokenAuth (regular user) attempted', function (done) {
        request(app)
            .post('/login')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should fail on /login (post) if good tokenAuth (admin user) attempted', function (done) {
        request(app)
            .post('/login')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(401, LOGIN_FAILED_RESPONSE, done)
    });

    it('should has authenticated user on /info (get) if good tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.user)
            .expect(200, {user: {name: 'user'}, authenticated: true}, done)
    });

    it('should has authenticated admin on /info (get) if good tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/info')
            .set('Authorization', 'Bearer ' + token.admin)
            .expect(200, {user: {name: 'admin', admin: true}, authenticated: true}, done)
    });

    it('should fail on /user if expired tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.old.user)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.old.admin)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.old.admin)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.old.user)
            .expect(401, EXPIRED_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.bad.user)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /user if expired tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/user')
            .set('Authorization', 'Bearer ' + token.bad.admin)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (admin user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.bad.admin)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });

    it('should fail on /admin if expired tokenAuth (regular user) attempted', function (done) {
        request(app)
            .get('/admin')
            .set('Authorization', 'Bearer ' + token.bad.user)
            .expect(401, INVALID_JWT_RESPONSE, done)
    });
});
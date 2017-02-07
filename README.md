[![Build Status][travis-image]][travis-url]
[![NPM Version][npm-image]][npm-url]
[![Node.js Version][node-version-image]][node-version-url]
[![NPM Downloads][downloads-image]][downloads-url]
[![Test Coverage][coveralls-image]][coveralls-url]

# auth-basic-jwt
Basic auth jwt module for express

#### Initialization

```
const authModule = require('auth-basic-jwt')
const auth = authModule(
    secret, // String or Buffer (can be forwarded by a promise) 
    getter, // function(userLogin) must return an object with at least user.pass so it can be compared with basic auth credentials (Object can be forwarded by a promise)
    options // see below
});
```

##### Options:

```
{
    token: {
        filter :function(user) or var,// data to put in the token
        exp :function(user) or var,
        iss :function(user) or var,  
        sub :function(user) or var,       
        aud :function(user) or var,       
    }
}
```

#### Usage
##### Example of usage 
```
const app = require('express')();
const auth = require('auth-basic-jwt')({
    secret: 'SECRET',
    getter: userGetter,
    /* options */
});

app.use(auth.core);

const routeA = require('./routes/routeA');
const routeB = require('./routes/routeB');
const routeC = require('./routes/routeC');

app.get('/userinfo', auth.user, yourFunction);

app.use('/a', routeA);
app.use('/b', auth.user, routeB);
app.use('/c', auth.admin, routeC);

function userGetter(userLogin) {
    return {
        email: userLogin,
        pass: 'password'
    }
}
// OR //
function userGetter(userLogin) {
    return Promise.resolve({email: userLogin, pass: 'password'});
}

```
in RouteA
```js
/// require ... ///

router.get('*', auth.user ,yourFunction);

module.exports = router;
```

[npm-image]: https://img.shields.io/npm/v/auth-basic-jwt.svg
[npm-url]: https://npmjs.org/package/auth-basic-jwt
[downloads-image]: https://img.shields.io/npm/dm/auth-basic-jwt.svg
[downloads-url]: https://npmjs.org/package/auth-basic-jwt
[travis-image]: https://img.shields.io/travis/maxx-t/auth-basic-jwt.svg
[travis-url]: https://travis-ci.org/maxx-t/auth-basic-jwt
[node-version-image]: https://img.shields.io/node/v/auth-basic-jwt.svg
[node-version-url]: https://nodejs.org/en/download
[coveralls-image]: https://img.shields.io/coveralls/maxx-t/auth-basic-jwt/master.svg
[coveralls-url]: https://coveralls.io/r/maxx-t/auth-basic-jwt?branch=master
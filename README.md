[![Build Status][travis-image]][travis-url]
[![NPM Version][npm-image]][npm-url]
[![Node.js Version][node-version-image]][node-version-url]
[![NPM Downloads][downloads-image]][downloads-url]
[![Test Coverage][coveralls-image]][coveralls-url]

# auth-basic-jwt
Basic auth jwt module for express

#### Initialization

```js
const authModule = require('auth-basic-jwt')
const auth = authModule(
    secret, // String or Buffer (can be forwarded by a promise) 
    userGetter, // function(userLogin) must return an object with at least a "pass" attribute in 
                // order to be compared with basic auth credentials (can be forwarded by a promise)
    options // see below
})
```
Note that the "_**userLogin**_" parameter must **match** the **expected basic auth login**

##### Options:

```js
{
    token: {
        filter :function(user) or var,// data to put in the token.user attribute (default is the whole user param without the pass attribute)
        exp :function(user) or var,
        iss :function(user) or var,  
        sub :function(user) or var,       
        aud :function(user) or var,       
    },
    session: {
        filter :function(user),// data to put in the req.user attribute (default is the whole user param without the pass attribute)
        // Note that the result of session.filter will be use as parameter for the token options 
    },
    password: {
        compare: function(user, pass):boolean // function used to compare the user password (user.pass) and the provided credential (pass). Default is (user.pass == pass)
    },
    unauthorized: function(req, res, next, message), // method )
    login: {
        path: string // path to match for a jwt request (default '/login') 
        method: string // method to match for a jwt request (default 'POST')
    }
}
```
- Note that the _**user**_ parameter is the object forwarded by your "**_userGetter_**"
- Be careful: if you don't set token.filter, _**user**_ must be an object, 
if you use mongoose for example ensure that it have been converted with the toObject method
in order to let the default filter [delete](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/delete) the _**pass**_ attribute

#### Usage
##### Example of usage 
```js
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

router.get('yourPath', auth.user ,yourFunction);

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

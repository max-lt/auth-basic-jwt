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
        filter :function(user) or var,// data to put in the token (default is {user: user})
        exp :function(user) or var,
        iss :function(user) or var,  
        sub :function(user) or var,       
        aud :function(user) or var,       
    }    
}
```
- Note that the "_user_" parameter is the object forwarded by your "**_userGetter_**"
- Be careful: is you define **_exp iss sub_** or **_aud_** in the first scope level of the filter function,
they will be overwritten if you set them as options too

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

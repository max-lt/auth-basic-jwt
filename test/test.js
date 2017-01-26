/**
 * Created by max on 26/01/17.
 */

var assert = require('assert');
var auth = require('..');
var http = require('http');
var request = require('supertest');
var app = require('express')();

describe('when no cookies are sent', function () {
    it('should default req.cookies to {}', function (done) {
        // request(server)
        //     .get('/')
        //     .expect(200, '{}', done)
    });

    it('should default req.signedCookies to {}', function (done) {
        // request(server)
        //     .get('/signed')
        //     .expect(200, '{}', done)
    });
});

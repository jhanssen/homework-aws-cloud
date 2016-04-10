/*global require,process,__filename*/

"use strict";

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongo = require('mongodb').MongoClient;
const jsondb = require('jsonfile');
const fs = require('fs');
const path = require('path');
const oauthserver = require('node-oauth2-server');
const email = require('emailjs');
const crypto = require('crypto');
const passwordless = require('passwordless');
const MongoStore = require('passwordless-mongostore');
const uuid = require('node-uuid');
const app = express();

const expressWs = require('express-ws')(app);

const root = path.resolve(fs.realpathSync(__filename), '../..') + path.sep;
//console.log(root);
const config = jsondb.readFileSync(root + 'config.json');
if (!config) {
    console.log('no config');
    process.exit();
}
if (!config.mongo) {
    console.log('no mongo');
    process.exit();
}
if (!config.secret) {
    console.log('no secret');
    process.exit();
}

passwordless.init(new MongoStore(config.mongo));

var mongodb, emailServer;
mongo.connect(config.mongo, (err, db) => {
    if (db) {
        console.log('connected to db');
        mongodb = db;

        var cfgCursor = db.collection("hwconfig").find();
        cfgCursor.each((err, doc) => {
            if (err) {
                console.error('failure to find hwconfig');
            } else if (doc) {
                config.db = doc;
                console.log('got mongo cfg', doc);

                if (config.db.email && config.db.email.smtp) {
                    var smtp = config.db.email.smtp;
                    var smtpConfig = {
                        user: smtp.username,
                        password: smtp.password,
                        host: smtp.host,
                        port: smtp.port ? smtp.port : 25,
                        ssl: smtp.ssl ? true : false
                    };
                    emailServer = email.server.connect(smtpConfig);
                    console.log("smtpconfig", smtpConfig);

                    passwordless.addDelivery(
                        function(tokenToSend, uidToSend, recipient, callback, req) {
                            var host = config.db.email.host;
                            emailServer.send({
                                text:    'Hello!\nAccess your account here: http://'
                                    + host + '/user/accept?token=' + tokenToSend + '&uid='
                                    + encodeURIComponent(uidToSend),
                                from:    config.db.email.from,
                                to:      recipient,
                                subject: 'Token for ' + host
                            }, function(err, message) {
                                if(err) {
                                    console.log(err);
                                }
                                callback(err);
                            });
                        });
                }
            }
        });
    }
});

const mongoose = require('mongoose');
mongoose.connect(config.mongo, (err, res) => {
    if (err) {
        console.log ('ERROR connecting to mongoose ' + err);
    } else {
        console.log ('Succeeded connected to mongoose');
        // app.oauth.server.options.model.create.client("balle", "balle2", []);
    }
});

app.oauth = oauthserver({
    model: require('./mongo-oauth.js'),
    grants: ['authorization_code', 'refresh_token'],
    debug: true
});
//console.log(app.oauth.server.options.model);

//app.use(app.oauth.authorize());

var wsUser = Object.create(null);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
    //secret: 'Laivozoo5I',
    secret: config.secret,
    resave: false,
    saveUninitialized: false
}));
app.use(passwordless.sessionSupport());

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log('listening on', port);
});

app.get('/', function (req, res) {
    if (req.session.passwordless) {
        res.redirect("/user/index");
        return;
    }
    res.redirect("/user/auth");
});

app.use(app.oauth.errorHandler());

app.get('/user/accept', passwordless.acceptToken(), function(req, res) {
    res.redirect('/user/index');
});

app.get('/user/auth', function(req, res) {
    var str = "<html><body><form method='POST'>" +
            "<input type='text' name='email'><br>" +
            "</form></body></html>";
    res.send(str);
});

app.post('/user/auth', passwordless.requestToken(function(user, delivery, callback, req) {
    let email = req.body.email;
    if (!email || typeof email !== "string" || !email.length) {
        callback(null, null);
        return;
    }
    mongodb.collection("hwusers").findOne({ email: email }, (err, doc) => {
        if (doc && doc.email == email) {
            // we're good
            callback(null, doc.email);
        } else {
            callback(null, null);
        }
    });
}, { failureRedirect: '/', userField: "email" }), function(req, res) {
    // success!
    res.redirect("/");
});

app.get('/user/index', passwordless.restricted({ failureRedirect: '/' }), function(req, res) {
    var str = `Hello ${req.session.passwordless}<br>` +
            '<a href="/user/generate">Generate key</a>';
    res.send(str);
});

app.get('/user/generate', passwordless.restricted({ failureRedirect: '/' }), function(req, res) {
    const key = uuid.v4();
    mongodb.collection("hwusers").update({ email: req.session.passwordless }, { $set: { key: key } }, (err, doc) => {
        if (err) {
            res.send("error");
        } else {
            var str = key + "<br>" +
                    '<a href="/user/index">Back</a>';
            res.send(str);
        }
    });
});

// Handle token grant requests
app.all('/oauth/token', app.oauth.grant());

// Show them the "do you authorise xyz app to access your content?" page
app.get('/oauth/authorize', function (req, res, next) {
    if (!req.session.user) {
        // If they aren't logged in, send them to your own login implementation
        res.redirect('/oauth/login?redirect=' + req.path + '&client_id=' +
                     req.query.client_id + '&redirect_uri=' + req.query.redirect_uri + '&state=' + req.query.state);
        return;
    }

    var str = "<html><body>Authorize?<br>" +
            "<form method='POST'>" +
            "<input type='submit' value='Yes'>" +
            `<input type='hidden' name='allow' value='yes'>` +
            `<input type='hidden' name='response_type' value='code'>` +
            `<input type='hidden' name='client_id' value='${req.query.client_id}'>` +
            `<input type='hidden' name='redirect_uri' value='${req.query.redirect_uri}'>` +
            `<input type='hidden' name='state' value='${req.query.state}'>` +
            "</form>" +
            "<form method='POST'>" +
            "<input type='submit' value='No'>" +
            `<input type='hidden' name='allow' value='no'>` +
            `<input type='hidden' name='client_id' value='${req.query.client_id}'>` +
            `<input type='hidden' name='redirect_uri' value='${req.query.redirect_uri}'>` +
            `<input type='hidden' name='state' value='${req.query.state}'>` +
            "</form>" +
            "</body></html>";
    res.send(str);
});

// Handle authorise
app.post('/oauth/authorize', function (req, res, next) {
    if (!req.session.user) {
        res.redirect('/oauth/login?client_id=' + req.query.client_id +
                     '&redirect_uri=' + req.query.redirect_uri + '&state=' + req.query.state);
        return;
    }

    next();
}, app.oauth.authCodeGrant(function (req, next) {
    // The first param should to indicate an error
    // The second param should a bool to indicate if the user did authorise the app
    // The third param should for the user/uid (only used for passing to saveAuthCode)
    next(null, req.body.allow === 'yes', req.session.user.id, req.session.user);
}));

// Show login
app.get('/oauth/login', function (req, res, next) {
    // res.render('login', {
    //     redirect: req.query.redirect,
    //     client_id: req.query.client_id,
    //     redirect_uri: req.query.redirect_uri
    // });
    var str = "<html><body><form method='POST'>" +
            "email: <input type='text' name='email'><br>" +
            `<input type='hidden' name='redirect' value='${req.query.redirect}'>` +
            `<input type='hidden' name='client_id' value='${req.query.client_id}'>` +
            `<input type='hidden' name='redirect_uri' value='${req.query.redirect_uri}'>` +
            `<input type='hidden' name='state' value='${req.query.state}'>` +
            "</form></body></html>";
    res.send(str);
});

// Handle login
app.post('/oauth/login', function (req, res, next) {
    // Insert your own login mechanism
    // see if we find ourselves in the db
    mongodb.collection("hwusers").findOne({ email: req.body.email }, (err, doc) => {
        if (doc) {
            if ("token" in doc && doc.token == req.body.token) {
                // Successful logins should send the user back to the /oauth/authorise
                // with the client_id and redirect_uri (you could store these in the session)
                mongodb.collection("hwusers").update({ email: req.body.email }, { $unset: { token: "" } });

                req.session.user = { id: req.body.email };
                res.redirect((req.body.redirect || '/home') + '?client_id=' +
                             req.body.client_id + '&redirect_uri=' + req.body.redirect_uri + '&state=' + req.body.state);
            } else {
                // generate random token and send it to the user, then wait for the user to enter the token
                const token = crypto.randomBytes(4).toString('hex');
                mongodb.collection("hwusers").update({ email: req.body.email }, { $set: { token: token } }, (err, doc) => {
                    var str =
                            "<html><body><form method='POST'>" +
                            "token: <input type='text' name='token'><br>" +
                            `<input type='hidden' name='email' value='${req.body.email}'><br>` +
                            `<input type='hidden' name='redirect' value='${req.body.redirect}'>` +
                            `<input type='hidden' name='client_id' value='${req.body.client_id}'>` +
                            `<input type='hidden' name='redirect_uri' value='${req.body.redirect_uri}'>` +
                            `<input type='hidden' name='state' value='${req.body.state}'>` +
                            "</form></body></html>";
                    res.send(str);

                    emailServer.send({
                        text: `token: ${token}`,
                        from: "admin@homework.software",
                        to: req.body.email,
                        subject: "homework token"
                    }, (err, msg) => {
                        console.log(`email with token ${token} sent to ${req.body.email}`, err, msg);
                    });
                });
            };
        } else {
            var str = "<html><body><form method='POST'>" +
                    "email: <input type='text' name='email'><br>" +
                    `<input type='hidden' name='redirect' value='${req.body.redirect}'>` +
                    `<input type='hidden' name='client_id' value='${req.body.client_id}'>` +
                    `<input type='hidden' name='redirect_uri' value='${req.body.redirect_uri}'>` +
                    `<input type='hidden' name='state' value='${req.body.state}'>` +
                    "</form></body></html>";
            res.send(str);
        }
    });
});

app.get('/secret', app.oauth.authorise(), function (req, res) {
    // Will require a valid access_token
    res.send('Secret area');
});

app.get('/public', function (req, res) {
    // Does not require an access_token
    res.send('Public area');
});

app.ws('/user/websocket', (ws, request) => {
    var user = request.session.passwordless;
    if (user in wsUser)
        wsUser[user].push(ws);
    else
        wsUser[user] = [ws];
    ws.on('close', () => {
        for (var i = 0; i < wsUser[user].length; ++i) {
            if (wsUser[user][i] == ws) {
                delete wsUser[user][i];
                return;
            }
        }
    });
    ws.on('message', (msg) => {
        console.log(`message from ${user}: ${msg}`);
    });
});

app.get('/privacy', (request, response) => {
    response.send('We do privacy!');
});

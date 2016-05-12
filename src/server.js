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

const Types = {
    Dimmer: 0,
    Light: 1,
    Fan: 2,
    Thermostat: 3,
    Clapper: 4,
    RGBWLed: 5,
    Sensor: 6,
    GarageDoor: 7,
    Lock: 8,
    Unknown: 99
};

// const root = path.resolve(fs.realpathSync(__filename), '../..') + path.sep;
// console.log(root);
// const config = jsondb.readFileSync(root + 'config.json');
// if (!config) {
//     console.log('no config');
//     process.exit();
// }

const config = {
    mongo: process.env.MONGOHQ_URL,
    secret: process.env.HOMEWORK_SECRET
};

if (!config.mongo) {
    console.log('no mongo');
    process.exit();
}
if (!config.secret) {
    console.log('no secret');
    process.exit();
}

passwordless.init(new MongoStore(config.mongo));

let stateSerial = 0;

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
                            console.log("about to send email to", recipient);
                            emailServer.send({
                                text:    'Hello!\nAccess your account here: https://'
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

function sendToAll(user, req)
{
    if (user in wsUser) {
        const data = JSON.stringify(req);
        const rs = wsUser[user].remotes;
        if (rs instanceof Array) {
            for (var i = 0; i < rs.length; ++i) {
                rs[i].send(data);
            }
        }
    }
}

function sendToUser(user, req)
{
    console.log("sendtouser", user, req);
    if (user in wsUser) {
        return wsUser[user].state.request(req);
    }
    console.log("user not present");
    return Promise.reject({ data: `User ${user} not found` });
}

function getDevices(user, cb)
{
    sendToUser(user, { type: "devices" }).then((hwresponse) => {
        hwresponse = hwresponse.data;
        let devs = Object.create(null);
        let rem = hwresponse.length;

        for (var i = 0; i < hwresponse.length; ++i) {
            let uuid = hwresponse[i].uuid;

            devs[uuid] = hwresponse[i];
            devs[uuid].values = Object.create(null);
            sendToUser(user, { type: "values", devuuid: uuid }).then(function(hwresponse) {
                hwresponse = hwresponse.data;
                if (hwresponse instanceof Array) {
                    for (var i = 0; i < hwresponse.length; ++i) {
                        var val = hwresponse[i];
                        devs[uuid].values[val.name] = val;
                    }
                }
                if (!--rem) {
                    wsUser[user].devices = devs;
                    if (cb)
                        cb(devs);
                }
            });
        }
    }).catch((err) => {
        console.error("sendtouser exception", err);
        cb(null);
    });
}

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
    console.log("authing", email);
    if (!email || typeof email !== "string" || !email.length) {
        callback(null, null);
        return;
    }
    console.log("looking up user");
    mongodb.collection("hwusers").findOne({ email: email }, (err, doc) => {
        console.log("got user from db");
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
            '<a href="/user/generate">Generate key</a><br>' +
            '<a href="/user/site/">Site</a>';
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
    let email = req.body.email;
    let loginStr = "<html><body><form method='POST'>" +
            "email: <input type='text' name='email'><br>" +
            `<input type='hidden' name='redirect' value='${req.body.redirect}'>` +
            `<input type='hidden' name='client_id' value='${req.body.client_id}'>` +
            `<input type='hidden' name='redirect_uri' value='${req.body.redirect_uri}'>` +
            `<input type='hidden' name='state' value='${req.body.state}'>` +
            "</form></body></html>";
    if (!email || typeof email !== "string" || !email.length) {
        res.send(loginStr);
        return;
    }
    mongodb.collection("hwusers").findOne({ email: email }, (err, doc) => {
        if (doc) {
            if ("token" in doc && doc.token == req.body.token) {
                // Successful logins should send the user back to the /oauth/authorise
                // with the client_id and redirect_uri (you could store these in the session)
                mongodb.collection("hwusers").update({ email: email }, { $unset: { token: "" } });

                req.session.user = { id: email };
                res.redirect((req.body.redirect || '/home') + '?client_id=' +
                             req.body.client_id + '&redirect_uri=' + req.body.redirect_uri + '&state=' + req.body.state);
            } else {
                // generate random token and send it to the user, then wait for the user to enter the token
                const token = crypto.randomBytes(4).toString('hex');
                mongodb.collection("hwusers").update({ email: email }, { $set: { token: token } }, (err, doc) => {
                    var str =
                            "<html><body><form method='POST'>" +
                            "token: <input type='text' name='token'><br>" +
                            `<input type='hidden' name='email' value='${email}'><br>` +
                            `<input type='hidden' name='redirect' value='${req.body.redirect}'>` +
                            `<input type='hidden' name='client_id' value='${req.body.client_id}'>` +
                            `<input type='hidden' name='redirect_uri' value='${req.body.redirect_uri}'>` +
                            `<input type='hidden' name='state' value='${req.body.state}'>` +
                            "</form></body></html>";
                    res.send(str);

                    emailServer.send({
                        text: `token: ${token}`,
                        from: "admin@homework.software",
                        to: email,
                        subject: "homework token"
                    }, (err, msg) => {
                        console.log(`email with token ${token} sent to ${email}`, err, msg);
                    });
                });
            };
        } else {
            res.send(loginStr);
        }
    });
});

function makeName(dev)
{
    let name = dev.name;
    if (dev.room)
        name = dev.room + " " + name;
    if (dev.floor)
        name = dev.floor + " " + name;
    return name;
}

function makeDimmer(dev)
{
    var dimmer = {
        actions: [
            "incrementPercentage",
            "decrementPercentage",
            "setPercentage",
            "turnOn",
            "turnOff"
        ],
        additionalApplianceDetails: {},
        applianceId: dev.uuid,
        friendlyDescription: dev.name,
        friendlyName: makeName(dev),
        isReachable: true,
        manufacturerName: "Homework",
        modelName: "HomeworkDimmer",
        version: "1.0"
    };

    return dimmer;
}

function makeSwitch(dev)
{
    var dimmer = {
        actions: [
            "turnOn",
            "turnOff"
        ],
        additionalApplianceDetails: {},
        applianceId: dev.uuid,
        friendlyDescription: dev.name,
        friendlyName: makeName(dev),
        isReachable: true,
        manufacturerName: "Homework",
        modelName: "HomeworkSwitch",
        version: "1.0"
    };

    return dimmer;
}

function makeThermostat(dev)
{
    var thermostat = {
        actions: [
            "incrementTargetTemperature",
            "decrementTargetTemperature",
            "setTargetTemperature"
        ],
        additionalApplianceDetails: {},
        applianceId: dev.uuid,
        friendlyDescription: dev.name,
        friendlyName: makeName(dev),
        isReachable: true,
        manufacturerName: "Homework",
        modelName: "HomeworkThermostat",
        version: "1.0"
    };
    return thermostat;
}

function setDeviceValue(user, dev, name, value)
{
    sendToUser(user, { type: "setValue", devuuid: dev.uuid, valname: name, value: value });
}

function addDeviceValue(user, dev, name, delta)
{
    sendToUser(user, { type: "addValue", devuuid: dev.uuid, valname: name, delta: delta });
}

const hwconvert = {
    fromHWTemperatureMode: function(mode) {
        switch (mode) {
        case "Heat":
            return "HEAT";
        case "Cool":
            return "COOL";
        case "Auto":
        case "Off":
            return "AUTO";
        }
        return undefined;
    },
    toHWTemperatureMode: function(mode) {
        switch (mode) {
        case "HEAT":
            return "Heat";
        case "COOL":
            return "Cool";
        case "AUTO":
            return "Auto";
        }
        return undefined;
    },
    ftoc: function(f) {
        return (f - 32) * 5/9;
    },
    ctof: function(c) {
        return (c * (9/5)) + 32;
    }
};

app.post('/oauth/request', (req, res) => {
    var event = req.body;

    var handlers = {
        "Alexa.ConnectedHome.Discovery": function() {
            console.log("hey Alexa.ConnectedHome.Discovery");
            const token = event.payload.accessToken;
            mongodb.collection("oauthaccesstokens").findOne({ accessToken: token }, (err, doc) => {
                if (doc && doc.accessToken == token) {
                    const user = doc.userId;

                    const discovery = {
                        "DiscoverAppliancesRequest": (response) => {
                            getDevices(user, (devs) => {
                                let appliances = [];

                                for (var uuid in devs) {
                                    switch (devs[uuid].type) {
                                    case Types.Dimmer:
                                        appliances.push(makeDimmer(devs[uuid]));
                                        break;
                                    case Types.Light:
                                    case Types.Fan:
                                        appliances.push(makeSwitch(devs[uuid]));
                                        break;
                                    case Types.Thermostat:
                                        appliances.push(makeThermostat(devs[uuid]));
                                        break;
                                    default:
                                        console.error(`unhandled device type ${uuid} ${devs[uuid].type}`);
                                        break;
                                    }
                                }

                                if (appliances.length > 0) {
                                    response.payload = {
                                        discoveredAppliances: appliances
                                    };
                                }

                                //console.log("sending", JSON.stringify(response));
                                res.send(JSON.stringify(response));
                            });
                        }
                    };

                    var response = {
                        header: {
                            namespace: "Alexa.ConnectedHome.Discovery",
                            name: "DiscoverAppliancesResponse",
                            payloadVersion: "2"
                        },
                        payload: ""
                    };

                    if (event.header.name in discovery) {
                        discovery[event.header.name](response);
                    } else {
                        console.error(event.header.name, "is not a valid discovery");
                        res.send(JSON.stringify(response));
                    }
                }
            });

        },
        "Alexa.ConnectedHome.Control": function() {
            const token = event.payload.accessToken;
            mongodb.collection("oauthaccesstokens").findOne({ accessToken: token }, (err, doc) => {
                if (doc && doc.accessToken == token) {
                    const user = doc.userId;


                    const deviceId = event.payload.appliance.applianceId;
                    const messageId = event.header.messageId;

                    var dev;
                    if (user in wsUser && wsUser[user].devices && deviceId in wsUser[user].devices)
                        dev = wsUser[user].devices[deviceId];
                    if (!dev) {
                        console.log(`no devices for ${user}`);
                        return;
                    }

                    const control = {
                        "TurnOnRequest": (response) => {
                            response.header.name = "TurnOnConfirmation";
                            response.payload = { };
                            console.log(`turning on device ${deviceId} with token ${token}`);

                            switch (dev.type) {
                            case Types.Dimmer:
                                setDeviceValue(user, dev, "level", dev.values.level.values.on);
                                break;
                            case Types.Light:
                            case Types.Fan:
                                setDeviceValue(user, dev, "value", 1);
                                break;
                            }
                            return true;
                        },
                        "TurnOffRequest": (response) => {
                            response.header.name = "TurnOffConfirmation";
                            response.payload = { };
                            console.log(`turning off device ${deviceId} with token ${token}`);

                            switch (dev.type) {
                            case Types.Dimmer:
                                setDeviceValue(user, dev, "level", dev.values.level.values.off);
                                break;
                            case Types.Light:
                            case Types.Fan:
                                setDeviceValue(user, dev, "value", 0);
                                break;
                            }
                            return true;
                        },
                        "SetPercentageRequest": (response, event) => {
                            response.header.name = "SetPercentageConfirmation";
                            response.payload = { };
                            let perc = event.percentageState.value;

                            switch (dev.type) {
                            case Types.Dimmer:
                                setDeviceValue(user, dev, "level", perc);
                                break;
                            }
                            return true;
                        },
                        "IncrementPercentageRequest": (response, event) => {
                            response.header.name = "IncrementPercentageConfirmation";
                            response.payload = { };
                            let delta = event.deltaPercentage.value;

                            switch (dev.type) {
                            case Types.Dimmer:
                                addDeviceValue(user, dev, "level", delta);
                                break;
                            }
                            return true;
                        },
                        "DecrementPercentageRequest": (response, event) => {
                            response.header.name = "DecrementPercentageConfirmation";
                            response.payload = { };
                            let delta = event.deltaPercentage.value;

                            switch (dev.type) {
                            case Types.Dimmer:
                                addDeviceValue(user, dev, "level", -delta);
                                break;
                            }
                            return true;
                        },

                        "SetTargetTemperatureRequest": (response, event) => {
                            console.log("settemp", deviceId);
                            response.header.name = "SetTargetTemperatureConfirmation";
                            sendToUser(user, { type: "values", devuuid: deviceId }).then(function(hwresponse) {
                                hwresponse = hwresponse.data;
                                if (hwresponse instanceof Array) {
                                    var mode, cooling, heating, temperature;

                                    for (var i = 0; i < hwresponse.length; ++i) {
                                        var val = hwresponse[i];
                                        switch (true) {
                                        case /^Mode$/.test(val.name):
                                            mode = val;
                                            break;
                                        case /^Cooling.*/.test(val.name):
                                            cooling = val;
                                            break;
                                        case /^Heating.*/.test(val.name):
                                            heating = val;
                                            break;
                                        case /^Temperature$/.test(val.name):
                                            temperature = val;
                                            break;
                                        }
                                    }

                                    if (mode === undefined || cooling === undefined || heating === undefined || temperature === undefined) {
                                        console.error(`temperature reply failure, mode '${mode}' cooling '${cooling}' heating '${heating}' temp '${temperature}'`);
                                        response.payload = {};
                                        res.send(JSON.stringify(response));
                                    } else {
                                        console.log("updating temp", mode, cooling, heating);
                                        let temp = event.targetTemperature.value;
                                        let isHeating = (mode.raw == "Heat");
                                        let tval = isHeating ? heating : cooling;

                                        console.log("temp", temp, "tval", JSON.stringify(tval));

                                        response.payload = {
                                            targetTemperature: {
                                                value: temp
                                            },
                                            temperatureMode: {
                                                value: hwconvert.fromHWTemperatureMode(mode.raw)
                                            },
                                            previousState: {
                                                targetTemperature: {
                                                    value: tval.units == "F" ? hwconvert.ftoc(tval.raw) : tval.raw
                                                },
                                                temperatureMode: {
                                                    value: hwconvert.fromHWTemperatureMode(mode.raw)
                                                }
                                            }
                                        };

                                        if (tval.units == "F")
                                            temp = hwconvert.ctof(temp);
                                        if (isHeating && temp < temperature.raw) {
                                            tval = cooling;
                                            setDeviceValue(user, dev, "Mode", "Cool");
                                        } else if (mode.raw == "Cool" && temp > temperature.raw) {
                                            tval = heating;
                                            setDeviceValue(user, dev, "Mode", "Heat");
                                        }
                                        setDeviceValue(user, dev, tval.name, temp);

                                        console.log("sending confirmation", JSON.stringify(response));
                                        res.send(JSON.stringify(response));
                                    }
                                }
                            });
                            return false;
                        },
                        "IncrementTargetTemperatureRequest": (response, event) => {
                            response.header.name = "IncrementTargetTemperatureConfirmation";
                            sendToUser(user, { type: "values", devuuid: deviceId }).then(function(hwresponse) {
                                hwresponse = hwresponse.data;
                                if (hwresponse instanceof Array) {
                                    var mode, cooling, heating;

                                    for (var i = 0; i < hwresponse.length; ++i) {
                                        var val = hwresponse[i];
                                        switch (true) {
                                        case /^Mode$/.test(val.name):
                                            mode = val;
                                            break;
                                        case /^Cooling.*/.test(val.name):
                                            cooling = val;
                                            break;
                                        case /^Heating.*/.test(val.name):
                                            heating = val;
                                            break;
                                        }
                                    }

                                    if (mode === undefined || cooling === undefined || heating === undefined) {
                                        console.error(`temperature reply failure, mode '${mode}' cooling '${cooling}' heating '${heating}'`);
                                        response.payload = {};
                                        res.send(JSON.stringify(response));
                                    } else {
                                        let delta = event.deltaTemperature.value;
                                        let tval = mode.raw == "Heat" ? heating : cooling;
                                        let newtemp = (tval.units == "F" ? hwconvert.ftoc(tval.raw) : tval.raw) + delta;

                                        response.payload = {
                                            targetTemperature: {
                                                value: newtemp
                                            },
                                            temperatureMode: {
                                                value: hwconvert.fromHWTemperatureMode(mode.raw)
                                            },
                                            previousState: {
                                                targetTemperature: {
                                                    value: tval.units == "F" ? hwconvert.ftoc(tval.raw) : tval.raw
                                                },
                                                temperatureMode: {
                                                    value: hwconvert.fromHWTemperatureMode(mode.raw)
                                                }
                                            }
                                        };

                                        if (tval.units == "F")
                                            newtemp = hwconvert.ctof(newtemp);
                                        setDeviceValue(user, dev, tval.name, newtemp);

                                        res.send(JSON.stringify(response));
                                    }
                                }
                            });
                            return false;
                        },
                        "DecrementTargetTemperatureRequest": (response, event) => {
                            response.header.name = "DecrementTargetTemperatureConfirmation";
                            sendToUser(user, { type: "values", devuuid: deviceId }).then(function(hwresponse) {
                                hwresponse = hwresponse.data;
                                if (hwresponse instanceof Array) {
                                    var mode, cooling, heating;

                                    for (var i = 0; i < hwresponse.length; ++i) {
                                        var val = hwresponse[i];
                                        switch (true) {
                                        case /^Mode$/.test(val.name):
                                            mode = val;
                                            break;
                                        case /^Cooling.*/.test(val.name):
                                            cooling = val;
                                            break;
                                        case /^Heating.*/.test(val.name):
                                            heating = val;
                                            break;
                                        }
                                    }

                                    if (mode === undefined || cooling === undefined || heating === undefined) {
                                        console.error(`temperature reply failure, mode '${mode}' cooling '${cooling}' heating '${heating}'`);
                                        response.payload = {};
                                        res.send(JSON.stringify(response));
                                    } else {
                                        let delta = event.deltaTemperature.value;
                                        let tval = mode.raw == "Heat" ? heating : cooling;
                                        let newtemp = (tval.units == "F" ? hwconvert.ftoc(tval.raw) : tval.raw) - delta;

                                        response.payload = {
                                            targetTemperature: {
                                                value: newtemp
                                            },
                                            temperatureMode: {
                                                value: hwconvert.fromHWTemperatureMode(mode.raw)
                                            },
                                            previousState: {
                                                targetTemperature: {
                                                    value: tval.units == "F" ? hwconvert.ftoc(tval.raw) : tval.raw
                                                },
                                                temperatureMode: {
                                                    value: hwconvert.fromHWTemperatureMode(mode.raw)
                                                }
                                            }
                                        };

                                        if (tval.units == "F")
                                            newtemp = hwconvert.ctof(newtemp);
                                        setDeviceValue(user, dev, tval.name, newtemp);

                                        res.send(JSON.stringify(response));
                                    }
                                }
                            });
                            return false;
                        },

                        "HealthCheckRequest": (response) => {
                            response.header.name = "HealthCheckResponse";
                            response.payload = {
                                description: "The system is currently healthy",
                                isHealthy: true
                            };
                            return true;
                        }
                    };

                    var response = {
                        header: {
                            namespace: "Alexa.ConnectedHome.Control",
                            payloadVersion: "2",
                            messageId: messageId
                        },
                        payload: ""
                    };

                    var send;
                    if (event.header.name in control) {
                        send = control[event.header.name](response, event.payload);
                    } else {
                        send = true;
                        console.error(event.header.name, "is not a valid control");
                    }

                    if (send)
                        res.send(JSON.stringify(response));
                } else {
                }
            });
        }
    };

    //console.log("heyevent", event);
    if (event.header.namespace in handlers) {
        handlers[event.header.namespace]();
    } else {
        console.error("Unknown execute request", JSON.stringify(event));
        res.send("bad");
    }
});

app.get('/user/create', (req, res) => {
    var str = "<html><body><form method='POST'>" +
            "email: <input type='text' name='email'><br>" +
            "key: <input type='password' name='key'><br>" +
            "<input type='submit' value='Create'>" +
            "</form></body></html>";
    res.send(str);
});

app.post('/user/create', (req, res) => {
    let key = config.db.creation;
    if (req.body.key !== key) {
        res.redirect('/');
    } else {
        let email = req.body.email;
        if (typeof email !== "string" || email.length == 0) {
            res.send("no email entered");
        } else {
            mongodb.collection("hwusers").insert({ email: email }, (err, result) => {
                if (err) {
                    res.send("error inserting user");
                } else {
                    res.redirect('/');
                }
            });
        }
    }
});

app.get(['/user/site', '/user/site*'], passwordless.restricted({ failureRedirect: '/' }), (req, res) => {
    if (req.url == "/user/site") {
        res.redirect('/user/site/');
        return;
    }
    let path = req.url.substr(10);
    if (path == "")
        path = "/";
    sendToUser(req.session.passwordless, { "type": "web", path: path }).then((data) => {
        data = data.data;
        res.set(data.statusCode);
        res.set(data.headers);
        res.end(data.body, data.binary ? "binary" : "utf8");
    });
});

app.ws('/user/site', (ws, request) => {
    let user = request.session.passwordless;
    if (!user) {
        console.log("closing because no pwless");
        ws.close();
        return;
    }
    if (wsUser[user].ready) {
        try {
            ws.send(JSON.stringify({ type: "ready", ready: true }));
        } catch (e) {
            console.log(e);
        }
    }
    if (!("remotes" in wsUser[user]))
        wsUser[user].remotes = [ws];
    else
        wsUser[user].remotes.push(ws);
    ws.on("close", () => {
        for (var i = 0; i < wsUser[user].remotes.length; ++i) {
            if (wsUser[user].remotes[i] == ws) {
                wsUser[user].remotes.splice(i, 1);
                break;
            }
        }
    });
    ws.on("message", (data) => {
        //console.log("got request", data);
        var json;
        try {
            json = JSON.parse(data);
        } catch (e) {
            return;
        }
        if ("id" in json) {
            json.wsid = json.id;
        }
        //console.log("sending to", user, JSON.stringify(json));
        sendToUser(user, json).then((resp) => {
            //console.log("got response back", JSON.stringify(resp));
            try {
                ws.send(JSON.stringify({ id: resp.id, result: resp.data }));
            } catch (e) {
                console.log(e);
            }
        }).catch((resp) => {
            try {
                ws.send(JSON.stringify({ id: resp.id, error: resp.data }));
            } catch (e) {
                console.log(e);
            }
        });
    });
});

app.ws('/user/websocket', (ws, request) => {
    let key = request.headers["x-homework-key"];
    if (typeof key !== "string" || !key.length) {
        console.log("no key, we're out");
        ws.close();
        return;
    }

    let serial = stateSerial++;
    let state = { id: 0, pending: Object.create(null), serial: serial };

    state.request = function(req) {
        var p = new Promise(function(resolve, reject) {
            var id = ++state.id;
            req.id = id;
            // this.log("sending req", JSON.stringify(req));
            state.pending[id] = { resolve: resolve, reject: reject };
            try {
                ws.send(JSON.stringify(req));
            } catch (e) {
                console.log(e);
            }
        });
        return p;
    };

    ws.on('close', () => {
        console.log("ws closed");
        if (!state.user)
            return;
        if (wsUser[state.user].state.serial != serial)
            return;

        delete wsUser[state.user];

        // reject all pending requests
        for (var p in state.pending) {
            state.pending[p].reject({ data: "socket closed" });
        }
        state = { id: 0, pending: Object.create(null) };
    });
    ws.on('message', (msg) => {
        if (state.user) {
            //console.log(`message from ${state.user}: ${msg}`);

            var json;
            try {
                json = JSON.parse(msg);
            } catch (e) {
                console.error("unable to parse json", msg, e);
                return;
            }

            if ("id" in json) {
                if (json.id in state.pending) {
                    let pending = state.pending[json.id];
                    delete state.pending[json.id];

                    if ("result" in json) {
                        pending.resolve({ data: json.result, id: json.wsid });
                    } else if ("error" in json) {
                        pending.reject({ data: json.error, id: json.wsid });
                    } else {
                        pending.reject({ data: "no result or error in json: " + JSON.stringify(json), id: json.wsid });
                    }
                } else {
                    console.error(`got message id ${json.id} but not in pending`);
                }
            } else if ("type" in json && json.type == "ready") {
                wsUser[state.user].ready = true;
                sendToAll(state.user, { type: "ready", ready: true });
                getDevices(state.user);
            } else {
                //console.error("got message with no id:", JSON.stringify(json));
                sendToAll(state.user, json);
            }
        } else {
            console.log("we're out");
            ws.close();
            return;
        }
    });

    // look up the key
    mongodb.collection("hwusers").findOne({ key: key }, (err, doc) => {
        if (!doc) {
            console.log("closing because of no doc");
            ws.close();
            return;
        }
        state.user = doc.email;
        wsUser[doc.email] = { state: state, ws: ws };

        try {
            ws.send(JSON.stringify({ type: "cloud", cloud: "login", user: state.user }));
        } catch (e) {
            console.log(e);
        }
    });
});

app.get('/privacy', (request, response) => {
    response.send('We do privacy!');
});

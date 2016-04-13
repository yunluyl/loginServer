//libraries
var express = require('express');
var path = require('path');
var logger = require('morgan');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var session = require('express-session');
var DynamoDBStore = require('connect-dynamodb')({session: session});
var AWS = require('aws-sdk');
//local files
var config = require('./config.js');
var func = require('./func.js');

var app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

//configure express
app.use(logger('combined'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(methodOverride('X-HTTP-Method-Override'));
app.set('trust proxy', 1);
app.use(session({
                secret: 'kyocsf4',
                saveUninitialized: false,
                resave: true,
                rolling: true,
                cookie: {secure: true, maxAge: 30000},
                store: new DynamoDBStore({
                                        client: new AWS.DynamoDB(),
                                        AWSRegion: 'us-east-1',
                                        table: 'sessions',
                                        reapInterval: 6000
                        })
            }));

app.use(function(req, res, next) {
    var err = req.session.error;
    var msg = req.session.notice;
    var success = req.session.success;

    delete req.session.error;
    delete req.session.notice;
    delete req.session.notice;

    if (err) res.locals.error = err;
    if (msg) res.locals.notice = msg;
    if (success) res.locals.success = success;

    next();
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

app.post('/login',func.login);
app.post('/refresh',func.refresh);
app.put('/signup',func.signup);

module.exports = app;

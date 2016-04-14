var AWS = require('aws-sdk');
var bcrypt = require('bcryptjs');
var nodemailer = require('nodemailer');
var uuid = require('node-uuid');
var config = require('./config');
//Constants
AWS.config.region = config.awsRegion;
AWS.config.apiVersion = config.wsApiVersion;

var cognitoidentity = new AWS.CognitoIdentity();
var dynamodb = new AWS.DynamoDB();
var transporter = nodemailer.createTransport(config.smtpConfig);

exports.refresh = function(req,res) {
    if (req.session && req.session.em) {
        cognitoidentity.getOpenIdTokenForDeveloperIdentity(new config.cognitoTokenParam(req.session.em),function(err, data) { 
            if (err) {
                res.status(500).send({err: config.errorDic['getTokenErr']});
            }
            else {
                res.status(200).send({AWSToken: data.Token});
            }
        });
    }
    else {
        res.status(307).send({rdt: 'ULG'}); //redirect to user login
    }
}

exports.login = function(req,res) {
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err,comResult) {
        if (err) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult) {
                dynamodb.getItem(new config.getParam(req.body.em),function(err,data) {
                    if (err) {
                        res.status(500).send({err: config.errorDic['AWSGetItem']});
                    }
                    else {
                        if (Object.keys(data).length !== 0) {
                            if (data.Item.hasOwnProperty('rp')) {
                                res.status(307).send({rdt: 'RSP'}); //redirect to reset password
                            }
                            else {
                                bcrypt.compare(req.body.pw,data.Item.ph.S,function(err,comResult) {
                                    if (err) {
                                        res.status(500).send({err: config.errorDic['bcryptErr']});
                                    }
                                    else {
                                        if (comResult) {
                                            cognitoidentity.getOpenIdTokenForDeveloperIdentity(new config.cognitoTokenParam(req.body.em),function(err, data) { if (err) {
                                                    res.status(500).send({err: config.errorDic['getTokenErr']});
                                                }
                                                else {
                                                    req.session.em = req.body.em;
                                                    res.status(200).send({AWSToken: data.Token});
                                                }
                                            });
                                        }
                                        else {
                                            res.status(401).send({err: config.errorDic['wrongPassword']});
                                        }
                                    }
                                });
                            }
                        }
                        else {
                            res.status(401).send({err: config.errorDic['userNotExist']});
                        }
                    }
                });
            }
            else {
                res.status(401).send({err: config.errorDic['wrongSignature']});
            }
        }
    });
}

exports.signup = function(req,res) {
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err,comResult) {
        if (err) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult) {
                bcrypt.hash(req.body.pw, config.saltRounds, function(err, hash) {
                    if (err) {
                        res.status(500).send({err: config.errorDic['bcryptErr']});
                    }
                    else {
                        var token = uuid.v4();
                        var expirationTime = new Date().getTime() + config.activationLinkExpireTime;
                        dynamodb.putItem(new config.putParam(req.body.em, hash, token, expirationTime), function(err, data) {
                            if (err) {
                                if (err.code === "ConditionalCheckFailedException") {
                                    res.status(400).send({err: config.errorDic['userExist']});
                                }
                                else {
                                    res.status(500).send(err);//{err: config.errorDic['AWSPutItem']}
                                }
                            }
                            else {
                                transporter.sendMail(new config.activationEmail(req.body.em,token), function(err,info) {
                                    if (err) {
                                        res.status(500).send({err: config.errorDic['sendEmailErr']}); //signup finished, but send email failed, need to resend activation email
                                    }
                                    else {
                                        res.status(200).send(); //signup sccessful
                                    }
                                });
                            }
                        });
                    }
                });
            }
            else {
                res.status(401).send({err: config.errorDic['wrongSignature']});
            }
        }
    });
}

/*
dynamodb.getItem(new config.getParam('b@b.com'),function(err,data) {
    if (err) {
        console.log('error!\n'+err);
    }
    else {
        console.log(data);
    }
});
*/

/*
dynamodb.putItem(new config.putParam('b@b.com','sdfsdsfsdfH79879'),function(err,data) {
    if (err) {
        console.log('error!\n'+err);
    }
    else {
        console.log(data);
    }
});
*/

/*
dynamodb.putItem(new config.editParam('c@c.com','sdfsdfsd5345',true),function(err,data) {
    if (err) {
        console.log('error!\n'+err);
    }
    else {
        console.log(data);
    }
})
*/






/*
var queryParam = function(email) {
    this.TableName = config.authTableName;
    this.IndexName = 'email-index';
    this.KeyConditionExpression = 'email = :useremail';
    this.ExpressionAttributeValues = {
        ':useremail': {'S':email}
    };
    this.ExpressionAttributeNames = {'#c': 'Count'};
    this.ProjectionExpression = '#c';
}
*/


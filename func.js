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

module.exports.refresh = function(req,res) {
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

module.exports.login = function(req,res) {
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err1,comResult) {
        if (err1) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult) {
                dynamodb.getItem(new config.getParam(req.body.em),function(err2,data) {
                    if (err2) {
                        res.status(500).send({err: config.errorDic['AWSGetItem']});
                    }
                    else {
                        if (Object.keys(data).length !== 0) {
                            if (data.Item.hasOwnProperty('rp')) {
                                res.status(307).send({rdt: 'RSP'}); //redirect to reset password
                            }
                            else {
                                bcrypt.compare(req.body.pw,data.Item.ph.S,function(err3,comResult) {
                                    if (err3) {
                                        res.status(500).send({err: config.errorDic['bcryptErr']});
                                    }
                                    else {
                                        if (comResult) {
                                            cognitoidentity.getOpenIdTokenForDeveloperIdentity(new config.cognitoTokenParam(req.body.em),function(err4, data) { 
                                                if (err4) {
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

module.exports.signup = function(req,res) {
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err1,comResult) {
        if (err1) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult) {
                bcrypt.hash(req.body.pw, config.saltRounds, function(err2, hash) {
                    if (err2) {
                        res.status(500).send({err: config.errorDic['bcryptErr']});
                    }
                    else {
                        var token = uuid.v4();
                        var expirationTime = new Date().getTime() + config.activationLinkExpireTime;
                        dynamodb.putItem(new config.putParam(req.body.em, hash, token, expirationTime.toString()), function(err3, data) {
                            if (err3) {
                                if (err.code === "ConditionalCheckFailedException") {
                                    res.status(400).send({err: config.errorDic['userExist']});
                                }
                                else {
                                    res.status(500).send({err: config.errorDic['AWSPutItem']});
                                }
                            }
                            else {
                                transporter.sendMail(new config.activationEmail(req.body.em,token), function(err4,info) {
                                    if (err4) {
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

module.exports.activate = function(req,res) {
    dynamodb.getItem(new config.getParam(req.body.em), function(err1,data) {
        if (err1) {
            res.status(500).send(err1+'\n'+req.body.em+req.body.tk); //{err: config.errorDic['AWSGetItem']}
        }
        else {
            if (Object.keys(data).length !== 0) {
                if (data.Item.hasOwnProperty('ep')) {
                    if (Number(data.Item.ep.N) > new Date().getTime()) {
                        if (data.Item.hasOwnProperty('tk')) {
                            if (req.body.tk === data.Item.tk.S) {
                                dynamodb.putItem(new editParam(req.body.em, data.Item.ph.S, '0'), function(err2, data) {
                                    if (err2) {
                                        res.status(500).send(err2); //need a webpage  REVISIT {err: config.errorDic['AWSEditItem']}
                                    }
                                    else {
                                        transporter.sendMail(new config.confirmEmail(req.body.em,'activationConfirm'), function(err3,info) {
                                            if (err3) {
                                                res.status(500).send(err3); //activation finished, but send email failed {err: config.errorDic['sendEmailErr']}
                                            }
                                            else {
                                                res.status(200).send('activation sccessful'); //activation sccessful
                                            }
                                        })
                                    }
                                });
                            }
                            else {
                                res.status(400).send({err: errorDic['activationTokenNotMatch']}); //need a webpage REVISIT
                            }
                        }
                        else {
                            res.status(500).send({err: errorDic['noActivationToken']}); //need a webpage REVISIT
                        }
                    }
                    else {
                        res.status(400).send({err: config.errorDic['activateTokenExpired']}); //need a webpage REVISIT
                    }
                }
                else {
                    res.status(400).send({err: config.errorDic['userHasActivated']}); //need a webpage REVISIT
                }
            }
            else {
                res.status(401).send({err: config.errorDic['userNotExist']}); //need a webpage  REVISIT
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


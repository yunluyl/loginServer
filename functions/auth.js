var AWS = require('aws-sdk');
var bcrypt = require('bcryptjs');
var nodemailer = require('nodemailer');
var uuid = require('node-uuid');
var config = require('../config');
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
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err1,comResult1) {
        if (err1) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult1) {
                dynamodb.getItem(new config.getParam(req.body.em),function(err2,data) {
                    if (err2) {
                        res.status(500).send({err: config.errorDic['AWSGetItem']});
                    }
                    else {
                        if (Object.keys(data).length !== 0) {
                            bcrypt.compare(req.body.pw,data.Item.ph.S,function(err3,comResult2) {
                                if (err3) {
                                    res.status(500).send({err: config.errorDic['bcryptErr']});
                                }
                                else {
                                    if (comResult2) {
                                        if (data.Item.hasOwnProperty('pe')) {
                                            if (Number(data.Item.pe.N) > new Date().getTime()) {
                                                cognitoidentity.getOpenIdTokenForDeveloperIdentity(new config.cognitoTokenParam(req.body.em),function(err4, tokenData) { 
                                                    if (err4) {
                                                        res.status(500).send({err: config.errorDic['getTokenErr']});
                                                    }
                                                    else {
                                                        req.session.em = req.body.em;
                                                        res.status(200).send({AWSToken: tokenData.Token, rdt: 'CPW'}); //redirect to change password
                                                    }
                                                });
                                            }
                                            else {
                                                res.status(401).send({err: config.errorDic['tempPasswordExpired']});
                                            }
                                        }
                                        else {
                                            cognitoidentity.getOpenIdTokenForDeveloperIdentity(new config.cognitoTokenParam(req.body.em),function(err5, tokenData) { 
                                                if (err5) {
                                                    res.status(500).send({err: config.errorDic['getTokenErr']});
                                                }
                                                else {
                                                    req.session.em = req.body.em;
                                                    if (data.Item.hasOwnProperty('ep')) {
                                                        res.status(200).send({AWSToken: tokenData.Token, rmd: 'UAA'}); //remind user the account is not activated
                                                    }
                                                    else {
                                                        res.status(200).send({AWSToken: tokenData.Token});
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    else {
                                        res.status(401).send({err: config.errorDic['wrongPassword']});
                                    }
                                }
                            });
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
    dynamodb.getItem(new config.getParam(req.query.em), function(err1,data1) {
        if (err1) {
            res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['awsGetItem']});
        }
        else {
            if (Object.keys(data1).length !== 0) {
                if (data1.Item.hasOwnProperty('ep')) {
                    if (Number(data1.Item.ep.N) > new Date().getTime()) {
                        if (data1.Item.hasOwnProperty('tk')) {
                            if (req.query.tk === data1.Item.tk.S) {
                                dynamodb.putItem(new config.editParam(req.query.em, data1.Item.ph.S), function(err2, data2) {
                                    if (err2) {
                                        res.render('activate',{title: 'Foodies account activation', message: config.activateMessage['AWSEditItem']});
                                    }
                                    else {
                                        transporter.sendMail(new config.confirmEmail(req.query.em,'activationConfirm'), function(err3,info) {
                                            if (err3) {
                                                res.render('activate',{title: 'Foodies account activation', message: config.activateMessage['sendEmailErr']}); //activation finished, but send email failed
                                            }
                                            else {
                                                res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['activationDone']});
                                            }
                                        })
                                    }
                                });
                            }
                            else {
                                res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['activationTokenNotMatch']});
                            }
                        }
                        else {
                            res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['noActivationToken']});
                        }
                    }
                    else {
                        res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['activateTokenExpired']});
                    }
                }
                else {
                    res.render('activate',{title: 'Foodies account activation', message : config.activateMessage['userHasActivated'].replace(/[%][s]/,req.query.em)});
                }
            }
            else {
                res.render('activate',{title: 'Foodies account activation', message : activateMessage['userNotExist'].replace(/[%][s]/,req.query.em)});
            }
        }
    });
}

module.exports.resetPassword = function(req, res) {
    bcrypt.compare(req.body.sg, config.iosSignatureHash, function(err1, comResult1) {
        if (err1) {
            res.status(500).send({err: config.errorDic['bcryptErr']});
        }
        else {
            if (comResult1) {
                dynamodb.getItem(new config.getParam(req.body.em), function(err2, data1) {
                    if (err2) {
                        res.status(500).send({err : errorDic['AWSGetItem']});
                    }
                    else {
                        if (Object.keys(data1).length !== 0) {
                            if (data1.Item.hasOwnProperty('ep')) {
                                res.status(401).send({err : config.errorDic['accountNotActive']});
                            }
                            else {
                                var randomPassword = config.generatePassword();
                                bcrypt.hash(randomPassword, config.saltRounds, function(err3, hash) {
                                    if (err3) {
                                        res.status(500).send({err: config.errorDic['bcryptErr']});
                                    }
                                    else {
                                        var passwordExpirationTime = new Date().getTime() + config.tempPasswordExpireTime;
                                        dynamodb.putItem(new config.editParam(req.body.em, hash, passwordExpirationTime), function(err4, data2) {
                                            if (err4) {
                                                res.status(500).send({err: config.errorDic['AWSPutItem']});
                                            }
                                            else {
                                                transporter.sendMail(new config.resetEmail(req.body.em,randomPassword), function(err5,info) {
                                                    if (err5) {
                                                        res.status(500).send({err: config.errorDic['sendEmailErr']}); //password reset finished, but send email failed, need to resend activation email
                                                    }
                                                    else {
                                                        res.status(200).send(); //password reset sccessful
                                                    }
                                                });
                                            }
                                        });
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

module.exports.changePassword = function(req, res) {
    if (req.session && req.session.em) {
        dynamodb.getItem(new config.getParam(req.session.em), function(err2, data1) {
            if (err2) {
                res.status(500).send({err : errorDic['AWSGetItem']});
            }
            else {
                if (Object.keys(data1).length !== 0) {
                    bcrypt.compare(req.body.pw, data1.Item.ph.S, function(err3, comResult2) {
                        if (comResult2) {
                            bcrypt.hash(req.body.np, config.saltRounds, function(err4, hash) {
                                if (err4) {
                                    res.status(500).send({err: config.errorDic['bcryptErr']});
                                }
                                else {
                                    dynamodb.putItem(new config.editParam(req.session.em, hash), function(err5, data2) {
                                        if (err5) {
                                            res.status(500).send({err : errorDic['AWSEditItem']});
                                        }
                                        else {
                                            res.status(200).send();
                                        }
                                    });
                                }
                            });
                        }
                        else {
                            res.status(401).send({err: config.errorDic['wrongPassword']});
                        }
                    });
                }
                else {
                    res.status(401).send({err: config.errorDic['userNotExist']});
                }
            }
        });
    }
    else {
        res.status(307).send({rdt: 'ULG'}); //redirect to user login
    }
}

module.exports.resendEmail = function(req, res) {
    if (req.session && req.session.em) {
        dynamodb.getItem(new config.getParam(req.session.em), function(err2, data1) {
            if (err2) {
                res.status(500).send({err : config.errorDic['AWSGetItem']});
            }
            else {
                if (Object.keys(data1).length !== 0) {
                    if (data1.Item.hasOwnProperty('tk')) {
                        var token = uuid.v4();
                        var expirationTime = new Date().getTime() + config.activationLinkExpireTime;
                        dynamodb.putItem(new config.editParam(req.session.em, data1.Item.ph.S, token, expirationTime), function(err3, data2) {
                            if (err3) {
                               res.status(500).send(err3); //{err: config.errorDic['AWSPutItem']}
                            }
                            else {
                                transporter.sendMail(new config.activationEmail(req.session.em,token), function(err4,info) {
                                    if (err4) {
                                        res.status(500).send({err: config.errorDic['sendEmailErr']}); //send email failed, need to resend activation email
                                    }
                                    else {
                                        res.status(200).send(); //resend email sccessful
                                    }
                                });
                            }
                        });
                    }
                    else {
                        res.status(400).send({err : config.errorDic['userHasActivated']});
                    }
                }
                else {
                    res.status(401).send({err : config.errorDic['userNotExist']});
                }
            }
        });
    }
    else {
        res.status(307).send({rdt: 'ULG'}); //redirect to user login
    }
}

module.exports.logout = function(req, res)
{
    if (req.session && req.session.em)
    {
        req.session.destroy(function(err2)
        {
            if (err2) 
            {
                res.status(500).send({err : config.errorDic['destroySessionErr']});
            }
            else
            {
                res.status(200).send();
            }
        });
    }
    else
    {
        res.status(307).send({rdt: 'ULG'}); //redirect to user login
    }
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


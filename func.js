var AWS = require('aws-sdk');
var bcrypt = require('bcryptjs');
//Constants
AWS.config.region = 'us-east-1';
AWS.config.apiVersion = {
    cognitoidentity: '2014-06-30',
    dynamodb: '2012-08-10'
};
var errorDic = {
    AWSGetItem:'AGI',
    userNotExist:'UNE',
    bcryptErr:'BCE',
    wrongPassword:'WPW',
    getTokenErr:'GTE',
    userExist:'URE',
    error7:'error7 occurred',
    error8:'error8 occurred',
    error9:'error9 occurred',
    error10:'error10 occurred',
};
var cognitoidentity = new AWS.CognitoIdentity();
var dynamodb = new AWS.DynamoDB();
const saltRounds = 10;
const authTableName = 'urs';

//Object definition
var putParam = function(email,passwordHash) {
    this.TableName = authTableName;
    this.Item = {
        'em':{S:email},
        'ph':{S:passwordHash}
    };
    this.ConditionExpression = 'attribute_not_exists(em)';
}

var getParam = function(email/*,ProjectionExpression1,ProjectionExpression2,...*/) {
    this.TableName = authTableName;
    this.Key = {
        'em':{S:arguments[0]}
    };
    if (arguments.length > 1) {
        this.ProjectionExpression = arguments[1];
        for (var i=2;i<arguments.length;i++) {
            this.ProjectionExpression += (','+arguments[i]);
        }
    }
}

var editParam = function(email,passwordHash,rstPass) {
    this.TableName = authTableName;
    this.Item = {
        'em':{S:email},
        'ph':{S:passwordHash},
    };
    if (rstPass) {
        this.Item['rp'] = {BOOL:true};
    }
    this.ConditionExpression = 'attribute_exists(em)';
}

var cognitoTokenParam = function(email) {
    this.IdentityPoolId = 'us-east-1:2ed0d413-562a-43db-b273-222585ff568d';
    this.Logins = {
        'login.test.developerLogin': email
    };
    this.TokenDuration = 3600;
}

exports.refresh = function(req,res) {
    if (req.session && req.session.em) {
        cognitoidentity.getOpenIdTokenForDeveloperIdentity(new cognitoTokenParam(req.session.em),function(err, data) { 
            if (err) {
                res.status(500).send({err: errorDic['getTokenErr']});
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
    dynamodb.getItem(new getParam(req.body.em),function(err,data) {
        if (err) {
            res.status(500).send(err);//{err: errorDic['AWSGetItem']}
        }
        else {
            if (Object.keys(data).length !== 0) {
                if (data.Item.hasOwnProperty('rp')) {
                    res.status(307).send({rdt: 'RSP'}); //redirect to reset password
                }
                else {
                    bcrypt.compare(req.body.pw,data.Item.ph.S,function(err,comResult) {
                        if (err) {
                            res.status(500).send({err: errorDic['bcryptErr']});
                        }
                        else {
                            if (comResult) {
                                cognitoidentity.getOpenIdTokenForDeveloperIdentity(new cognitoTokenParam(req.body.em),function(err, data) { if (err) {
                                        res.status(500).send({err: errorDic['getTokenErr']});
                                    }
                                    else {
                                        req.session.em = req.body.em;
                                        res.status(200).send({AWSToken: data.Token});
                                    }
                                });
                            }
                            else {
                                res.status(401).send({err: errorDic['wrongPassword']});
                            }
                        }
                    });
                }
            }
            else {
                res.status(401).send({err: errorDic['userNotExist']});
            }
        }
    });
}

exports.signup = function(req,res) {
    bcrypt.hash(req.body.pw, saltRounds, function(err, hash) {
        if (err) {
            res.status(500).send({err: errorDic['bcryptErr']});
        }
        else {
            dynamodb.putItem(new putParam(req.body.em, hash), function(err, data) {
                if (err) {
                    res.status(500).send(err);
                }
                else {
                    res.status(200).send(); //signup sccessful
                }
            });
        }
    });
}

/*
dynamodb.getItem(new getParam('b@b.com'),function(err,data) {
    if (err) {
        console.log('error!\n'+err);
    }
    else {
        console.log(data);
    }
});
*/

/*
dynamodb.putItem(new putParam('b@b.com','sdfsdsfsdfH79879'),function(err,data) {
    if (err) {
        console.log('error!\n'+err);
    }
    else {
        console.log(data);
    }
});
*/

/*
dynamodb.putItem(new editParam('c@c.com','sdfsdfsd5345',true),function(err,data) {
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
    this.TableName = authTableName;
    this.IndexName = 'email-index';
    this.KeyConditionExpression = 'email = :useremail';
    this.ExpressionAttributeValues = {
        ':useremail': {'S':email}
    };
    this.ExpressionAttributeNames = {'#c': 'Count'};
    this.ProjectionExpression = '#c';
}
*/


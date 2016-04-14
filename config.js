var consts = {
    saltRounds : 10,
    authTableName : 'urs',
    awsRegion : 'us-east-1',
    IdentityPoolId : 'us-east-1:2ed0d413-562a-43db-b273-222585ff568d',
    awsTokenDuration : 3600,
    sessionSecret : 'kyocsf4',
    sessionSaveUninitialized : false,
    sessionResave : true,
    sessionRolling : true,
    sessionSecure : true,
    sessionMaxAge : 604800000,
    sessionTableName : 'sessions',
    sessionReapInterval : 0,
    iosSignatureHash : '$2a$12$TIxeS9KNBulfcris.V51q..WJb9K3ZXjphU4kzuhvMa5OzEaJeQre',
    activationLinkExpireTime : 900000  //unit: ms
};

var errorDic = {
    AWSGetItem:'AGI',
    userNotExist:'UNE',
    bcryptErr:'BCE',
    wrongPassword:'WPW',
    getTokenErr:'GTE',
    userExist:'URE',
    AWSPutItem:'API',
    wrongSignature:'WSG',
    sendEmailErr:'SEE',
    error10:'error10 occurred'
};

var awsApiVersion = {
    cognitoidentity: '2014-06-30',
    dynamodb: '2012-08-10'
};

var smtpConfig = {
    host: 'smtp.mailgun.org',
    port: 2525,
    secure: false,
    requireTLS: true,
    connectionTimeout: 1000,
    greetingTimeout: 1000,
    auth: {
        user: 'postmaster@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org',
        pass: '23898fa13f1882e0b11424081e9db139'
    }
};

var activationEmail = function(sendto,token) {
    this.from = '"Foodies" <foodies@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org>';
    this.to = sendto;
    this.subject = 'Account Activation';
    this.text = 'https://foodloginserver.herokuapp.com/activate?em='+sendto+'&tk='+token;
};

var resetEmail = function(sendto,tempPassword) {
    this.from = '"Foodies" <foodies@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org>';
    this.to = sendto;
    this.subject = 'Reset Password';
    this.text = tempPassword;
};

var putParam = function(email,passwordHash,token,expirationTime) {
    this.TableName = consts.authTableName;
    this.Item = {
        'em':{S:email},
        'ph':{S:passwordHash},
        'tk':{S:token},
        'ep':{N:expirationTime}
    };
    this.ConditionExpression = 'attribute_not_exists(em)';
}

var getParam = function(email/*,ProjectionExpression1,ProjectionExpression2,...*/) {
    this.TableName = consts.authTableName;
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
    this.TableName = consts.authTableName;
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
    this.IdentityPoolId = consts.IdentityPoolId;
    this.Logins = {
        'login.test.developerLogin': email
    };
    this.TokenDuration = consts.awsTokenDuration;
}

module.exports = consts;
module.exports.errorDic = errorDic;
module.exports.awsApiVersion = awsApiVersion;
module.exports.putParam = putParam;
module.exports.getParam = getParam;
module.exports.editParam = editParam;
module.exports.cognitoTokenParam = cognitoTokenParam;
module.exports.smtpConfig = smtpConfig;
module.exports.activationEmail = activationEmail;
module.exports.resetEmail = resetEmail;
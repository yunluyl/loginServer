var consts = module.exports = {
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
    activationLinkExpireTime : 900000,  //unit: ms
    emailSender : '"Foodies" <foodies@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org>'
};

var errorDic = module.exports.errorDic = {
    AWSGetItem:'AGI',
    userNotExist:'UNE',
    bcryptErr:'BCE',
    wrongPassword:'WPW',
    getTokenErr:'GTE',
    userExist:'URE',
    AWSPutItem:'API',
    wrongSignature:'WSG',
    sendEmailErr:'SEE',
    AWSEditItem:'AEI',
    tempPasswordExpired:'TPE',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred'
};

var activateMessage = module.exports.activateMessage = {
    AWSGetItem:'ERROR: Internal error occured while getting data from the database',
    activationDone:'Account has been successfully activated!',
    AWSEditItem:'ERROR: Internal error occured while updating data in the database',
    sendEmailErr:'Activation has completed, but confirmation email did not send out because of email server error',
    activationTokenNotMatch:'ERROR: Wrong activation token value',
    noActivationToken:'ERROR: Internal error occured, no token value exist in the database',
    activateTokenExpired:'ERROR: The activation link has expired, please resend activation email',
    userHasActivated:'ERROR: User %s has been activated before',
    userNotExist:'ERROR: User %s do not exist',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred',
    error10:'error10 occurred'
};

var awsApiVersion = module.exports.awsApiVersion = {
    cognitoidentity: '2014-06-30',
    dynamodb: '2012-08-10'
};

var smtpConfig = module.exports.smtpConfig = {
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

var activationEmail = module.exports.activationEmail = function(sendto,token) {
    this.from = consts.emailSender;
    this.to = sendto;
    this.subject = 'Account Activation';
    this.text = 'https://foodloginserver.herokuapp.com/api/activate?em='+sendto+'&tk='+token;
};

var resetEmail = module.exports.resetEmail = function(sendto,tempPassword) {
    this.from = consts.emailSender;
    this.to = sendto;
    this.subject = 'Reset Password';
    this.text = tempPassword;
};

var confirmEmail = module.exports.confirmEmail = function(sendto,category) {
    this.from = consts.emailSender;
    this.to = sendto;
    switch (category) {
        case 'activationConfirm':
            this.subject = 'Activation Confirmation';
            this.text = 'Your account has been successfully activated';
            break;
    }
}

var putParam = module.exports.putParam = function(email,passwordHash,token,expirationTime) {
    this.TableName = consts.authTableName;
    this.Item = {
        'em':{S:email},
        'ph':{S:passwordHash},
        'tk':{S:token},
        'ep':{N:expirationTime}
    };
    this.ConditionExpression = 'attribute_not_exists(em)';
}

var getParam = module.exports.getParam = function(email/*,ProjectionExpression1,ProjectionExpression2,...*/) {
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

var editParam = module.exports.editParam = function(email,passwordHash,passwordExpireTime) {
    this.TableName = consts.authTableName;
    this.Item = {
        'em':{S:email},
        'ph':{S:passwordHash},
    };
    if (passwordExpireTime !== '0') {
        this.Item['pe'] = {N:passwordExpireTime};
    }
    this.ConditionExpression = 'attribute_exists(em)';
}

var cognitoTokenParam = module.exports.cognitoTokenParam = function(email) {
    this.IdentityPoolId = consts.IdentityPoolId;
    this.Logins = {
        'login.test.developerLogin': email
    };
    this.TokenDuration = consts.awsTokenDuration;
}

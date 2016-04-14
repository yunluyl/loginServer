var nodemailer = require('nodemailer');
var smtpConfig = {
    host: 'smtp.mailgun.org',
    port: 2525,
    secure: false,
    requireTLS: true,
    connectionTimeout: 500,
    auth: {
        user: 'postmaster@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org',
        pass: '23898fa13f1882e0b11424081e9db139'
    }
};

var transporter = nodemailer.createTransport(smtpConfig);

var mailOptions = {
    from: '"Foodies" <foodies@sandboxc8c4690cc28f4f6a9ce82305a3fcfbdf.mailgun.org>',
    to: 'luyun198993@gmail.com',
    subject: 'Account activation',
    text: 'Hello\nThis is a test email\nhttps://foodloginserver.herokuapp.com/activate'
};

transporter.sendMail(mailOptions, function(err,info) {
    if (err) {
        console.log(err);
    }
    else {
        console.log('Message send: ' + info);
    }
});
var express = require('express');
var auth = require('../functions/auth');
var utility = require('../functions/utility');
var router = express.Router();

router.post('/login', auth.login);
router.post('/refresh', auth.refresh);
router.put('/signup', auth.signup);
router.get('/activate', auth.activate);
router.post('/reset', auth.resetPassword);
router.post('/change', auth.changePassword);
router.get('/resend', auth.resendEmail);
router.delete('/logout', auth.logout);
router.get('/time', utility.serverTime);

module.exports = router;

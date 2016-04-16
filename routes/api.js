var express = require('express');
var auth = require('../auth');
var router = express.Router();

router.post('/login', auth.login);
router.post('/refresh', auth.refresh);
router.put('/signup', auth.signup);
router.get('/activate', auth.activate);

module.exports = router;

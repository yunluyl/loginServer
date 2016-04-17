module.exports.serverTime = function(req, res)
{
    if (req.session && req.session.em)
    {
        res.status(200).send({tm : (new Date().getTime()).toString});
    }
    else
    {
        res.status(401).send({rdt : 'ULG'});
    }
}

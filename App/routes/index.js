var express = require('express');
var router = express.Router();

const saltRounds = 10;

/* GET home page. */
router.get('/', function(req, res, next) {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
});

router.post('/register', (req, res, next) => {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
  var username = req.body.username;
  var password = req.body.password;
  _hash(password, saltRounds, function(err, hash) {
    if (err)
      throw err;
    toWrite = username + ';' + hash + '\n';
    appendFile('../../users.txt', toWrite, function(err) {
       if (err)
         throw err;
     });
});
})

module.exports = router;

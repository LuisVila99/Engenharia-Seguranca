var express = require('express');
var router = express.Router();

const saltRounds = 10;
const bcrypt = require('bcrypt');
const fs = require('fs');

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
  bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err)
      throw err;
    toWrite = username + ';' + hash + '\n';
    console.log(toWrite);
    fs.appendFile('../users.txt', toWrite, function(err) {
       if (err)
         throw err;
     });
});
})


router.post('/login', async (req, res, next) => {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
  var username = req.body.username1;
  var password = req.body.password2;
  fs.readFile('../users.txt', 'utf8' , (err, data) => {
    if (err) {
      throw err;
    }
      login_aux(username, password, data);
  });
});

async function login_aux(username, password, data) {
	var entries = data.split('\n');

	for (let i = 0; i < entries.length - 1; i++){
		var us_pa = entries[i].split(';');
		var match = await bcrypt.compare(password, us_pa[1]);
		if(us_pa[0] == username && match){
			console.log('Login successful');
			return true;
		}
		if(us_pa[0] == username && !match){
			console.log('Wrong password');
			return false;
		}
	}
	console.log('No such username');
	return false;
}

module.exports = router;

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

router.post('/', (req, res, next) => {
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
     x = __dirname.split('/routes')[0] + '/views/login.html';
     res.sendFile(x);
});
})




router.post('/login', async (req, res, next) => {
  var username = req.body.username2;
  var password = req.body.password2;
  fs.readFile('../users.txt', 'utf8' , async (err, data) => {
    if (err) {
      throw err;
    }
      x = await login_aux(username, password, data);
      if(x){
          x = __dirname.split('/routes')[0] + '/views/home.html';
          console.log('here');
          res.sendFile(x);
      }
      else{
        console.log('here2')
        x = __dirname.split('/routes')[0] + '/views/login.html';
        res.sendFile(x);
      };
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

var express = require('express');
var router = express.Router();

const saltRounds = 10;
const bcrypt = require('bcrypt');
const fs = require('fs');
const alert = require('alert');
const axios = require('axios');

/* GET home page. */
router.get('/', function(req, res, next) {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
});

router.post('/', (req, res, next) => {
  var username = req.body.username;
  var password = req.body.password;
  var ok = true;

  //verifica username
  fs.readFile('../users.txt', 'utf8', (err, data) => {
    if(err) throw err;
    var entries = data.split('\n');
    for (let i = 0; i < entries.length - 1; i++){
      if(username == entries[i].split(';')[0]){
        alert('Username already exists!');
        ok = false;
        console.log(ok);
      }
    }
  })
  setTimeout(function(){if(ok){
    console.log(ok);
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err)
        throw err;
      toWrite = username + ';' + hash + '\n';
      console.log(toWrite);
      fs.appendFile('../users.txt', toWrite, function(err) {
         if (err)
           throw err;
       });
    });}}, 3000);
  
  

    x = __dirname.split('/routes')[0] + '/views/login.html';
    res.sendFile(x);
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


router.get('/mycertificates', (req, res, next) => {
  axios.get('https://fedora:8443/pki/request')
  .then((res) => {
    console.log(res.data);
  });
});

module.exports = router;

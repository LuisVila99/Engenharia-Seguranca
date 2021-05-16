const fs = require('fs');
const bcrypt = require('bcrypt');
const saltRounds = 10;


function register(username, password){
	bcrypt.hash(password, saltRounds, function(err, hash) {
    	if (err)
    		throw err;
    	toWrite = username + ';' + hash + '\n';
    	fs.appendFile('./users.txt', toWrite, function(err) {
     		if (err)
     			throw err;
   		});
	});
	
};

async function login(username, password){
	fs.readFile('./users.txt', 'utf8' , (err, data) => {
  		if (err) {
    		throw err;
  		}
  			login_aux(username, password, data);
	});
}

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







//register('luis', 'pass');
//register('jose', 'blab');
//register('zeca', 'okok');
//register('joao', 'joao');
login('luis', 'pass');
login('andre', 'what');
login('joao', 'pass');
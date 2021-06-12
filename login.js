import { appendFile, readFile } from './node_modules/fs';
import { hash as _hash, compare } from './node_modules/bcrypt';
//const fs = require('fs');
//const bcrypt = require('bcrypt');
const saltRounds = 10;


function register(){
	var username = document.getElementById("username").value
	var password = document.getElementById("password").value
	_hash(password, saltRounds, function(err, hash) {
    	if (err)
    		throw err;
    	toWrite = username + ';' + hash + '\n';
    	appendFile('./users.txt', toWrite, function(err) {
     		if (err)
     			throw err;
   		});
	});
	
};

async function login(){
	var username = document.getElementById("username2").value
	var password = document.getElementById("password2").value
	readFile('./users.txt', 'utf8' , (err, data) => {
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
		var match = await compare(password, us_pa[1]);
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
//login('luis', 'pass');
//login('andre', 'what');
//login('joao', 'pass');
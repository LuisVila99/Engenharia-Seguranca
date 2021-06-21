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


router.post('/mycertificates', async (req, res, next) => {

  var username = req.body.username3;
  var password = req.body.password3;
  var dt = fs.readFileSync('../users.txt', 'utf8');
  console.log(username);
  console.log(password);
  if(!login_aux(username, password, dt)){
    console.log('Auth error');
    return;
  }

  axios.get('https://fedora:8443/ca/rest/certs')
  .then((res) => {
    //console.log(res.data.entries[11].id);

    fs.readFile('../certs.txt', 'utf8', async (err, data) => {
      if(err) throw err;
      var lines = data.split('\n');
      for(let i = 0; i < lines.length-1; i++){
        var us_cert = lines[i].split(';');
        //console.log(res.data.total);
        for(let j = 0; j < res.data.total; j++){
          // Receber username por input
          if(us_cert[0] == username && us_cert[1] == res.data.entries[j].id){
            console.log(res.data.entries[j]);
          }
        }
      }
    })
  });
  x = __dirname.split('/routes')[0] + '/views/home.html';
  console.log('here');
  res.sendFile(x);
});



router.post('/newcertificate', (req, res, next) => {
  var dat = {
    "Attributes": {
      "Attribute": []
    },
    "ProfileID": "caServerKeygen_UserCert",
    "Renewal": false,
    "Input": [
      {
        "id": "i1",
        "ClassID": "serverKeygenInputImpl",
        "Name": "Server-Side Key Generation",
        "Text": null,
        "Attribute": [
          {
            "name": "serverSideKeygenP12Passwd",
            "Value": "Secret.123",
            "Descriptor": {
              "Syntax": "server_side_keygen_request_type",
              "Constraint": null,
              "Description": "Server-Side Key Generation P12 Password",
              "DefaultValue": null
            }
          },
          {
            "name": "keyType",
            "Value": "RSA",
            "Descriptor": {
              "Syntax": "server_side_keygen_key_type",
              "Constraint": null,
              "Description": "Server-Side Key Generation Key Type",
              "DefaultValue": null
            }
          },
          {
            "name": "keySize",
            "Value": "1024",
            "Descriptor": {
              "Syntax": "server_side_keygen_key_size",
              "Constraint": null,
              "Description": "Server-Side Key Generation Key Size",
              "DefaultValue": null
            }
          }
        ],
        "ConfigAttribute": []
      },
      {
        "id": "i2",
        "ClassID": "subjectNameInputImpl",
        "Name": "Subject Name",
        "Text": null,
        "Attribute": [
          {
            "name": "sn_uid",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "UID",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_e",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Email",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_cn",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Common Name",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_ou3",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Organizational Unit 3",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_ou2",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Organizational Unit 2",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_ou1",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Organizational Unit 1",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_ou",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Organizational Unit",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_o",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Organization",
              "DefaultValue": null
            }
          },
          {
            "name": "sn_c",
            "Value": "PT",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Country",
              "DefaultValue": null
            }
          }
        ],
        "ConfigAttribute": []
      },
      {
        "id": "i3",
        "ClassID": "submitterInfoInputImpl",
        "Name": "Requestor Information",
        "Text": null,
        "Attribute": [
          {
            "name": "requestor_name",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Requestor Name",
              "DefaultValue": null
            }
          },
          {
            "name": "requestor_email",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Requestor Email",
              "DefaultValue": null
            }
          },
          {
            "name": "requestor_phone",
            "Value": "1",
            "Descriptor": {
              "Syntax": "string",
              "Constraint": null,
              "Description": "Requestor Phone",
              "DefaultValue": null
            }
          }
        ],
        "ConfigAttribute": []
      }
    ]
  }


  var username = req.body.username4;
  var password = req.body.password4;
  var dt = fs.readFileSync('../users.txt', 'utf8');
  console.log(username);
  console.log(password);
  if(!login_aux(username, password, dt)){
    console.log('Auth error');
    return;
  }

  //requestURL: 'https://fedora:8443/ca/rest/certrequests/18'


  axios.post('https://fedora:8443/ca/rest/certrequests/', dat).then( (res) => {
    console.log(res.data);
    var str = res.data.entries[0].requestURL;
    console.log(str);
    console.log('aqui');
    var num = parseInt(str.split('/')[str.split('/').length - 1]).toString(16);
    num = '0x' + num;
    console.log(num);
    var write = username + ';' + num + '\n';
    fs.appendFile('../certs.txt', write, function(err) {
      if (err)
        throw err;
    });

  }).catch( () => {});

  x = __dirname.split('/routes')[0] + '/views/home.html';
  console.log('here');
  res.sendFile(x);
});



module.exports = router;

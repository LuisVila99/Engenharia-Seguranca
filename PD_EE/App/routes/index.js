var express = require('express');
var router = express.Router();

const saltRounds = 10;
const bcrypt = require('bcrypt');
const fs = require('fs');
const alert = require('alert');
const axios = require('axios');
const exec = require('child_process').exec;
const { SSL_OP_EPHEMERAL_RSA } = require('constants');
const writeline = require('prompt');

var logged_user = ''; // variável onde se guarda o nome de utilizador que inicia sessão na aplicação

// Lista de caracteres aceites para validação de input
const whitelist = ('1234567890'+'abcdefghijklmnopqrstuvwxyz'+'abcdefghijklmnopqrstuvwxyz'.toUpperCase()+'_').split('');

// Função que servirá para validação de input, verificando se algum caracter do input não pertence à lista de caracteres permitidos
function validate_input(input){
  for(let i = 0; i < input.length; i++){
    if(!whitelist.includes(input[i])) return false;
  }
  return true;
}


/* GET home page. */
// Carrega o HTML da página inicial ao lançar a aplicação
router.get('/', function(req, res, next) {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
});


// Registo de um utilizador 
router.post('/', (req, res, next) => {
  var username = req.body.username; // input do username
  var password = req.body.password; // input da password
  var ok = true;

  if(!(validate_input(username) && validate_input(password))){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/login.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }
  else {
  fs.readFile('../users.txt', 'utf8', (err, data) => { //verifica se o username é único 
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
      fs.appendFile('../users.txt', toWrite, function(err) { //caso o username não exista já e se verifique a validação do input, regista o novo user
         if (err)
           throw err;
       });
    });}}, 3000);
  }
    x = __dirname.split('/routes')[0] + '/views/login.html'; //recarrega o hmtl 
    res.sendFile(x);
    
})



// Login na aplicação 
router.post('/login', async (req, res, next) => {
  var username = req.body.username2; //input de username 
  var password = req.body.password2; //input de password

  if(!(validate_input(username) && validate_input(password))){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/login.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }
  else {
    fs.readFile('../users.txt', 'utf8' , async (err, data) => {
      if (err) {
        throw err;
      }
        x = await login_aux(username, password, data); //espera resultado da função auxiliar
        if(x){
            logged_user = username; //guardar nome de utilizador que inicia sessão na aplicação
            if(logged_user == 'admin'){
              x = __dirname.split('/routes')[0] + '/views/admin.html'; // carrega a página principal da aplicação se login estiver correto
              res.sendFile(x);
            }
            else{
              x = __dirname.split('/routes')[0] + '/views/home.html'; // carrega a página principal da aplicação se login estiver correto
              res.sendFile(x);
            }            
        }
        else{
          x = __dirname.split('/routes')[0] + '/views/login.html'; // se o login estiver errado recerrega a página de registo/autenticação
          res.sendFile(x);
        };
    });
  }
});

//Função auxiliar que verifica se um nome de utilizador e respetiva password se encontram no ficheiro onde estes são guardados
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
			alert('Wrong password');
			return false;
		}
	}
	alert('No such username');
	return false;
}


router.post('/newcertificate', async (req, res, next) => {  
    try {
      y = __dirname.split('/routes')[0] + '/views/newcert.html'; // carrega a página principal da aplicação se login estiver correto
      res.sendFile(y);
    } catch (error) {
        throw error;
    }
});



router.post('/newcertificateemit', async (req, res, next) => {
  var request = req.body.request; //input de request
  var country = req.body.country;
  var organization = req.body.organization;
  var common = req.body.common;

  if(!(validate_input(request) && validate_input(country) && validate_input(organization)  && validate_input(common) )){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/newcert.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
    await create_config(country, organization, common);
    exec('sudo openssl req -new -config ./serv.cnf -key /root/ca/private/cakey.pem -out /root/ca/requests/' + request + '.csr', { encoding: 'utf-8' });

    // regista em 'certs.txt' a que utilizador corresponde o novo pedido de certificado
    var write = logged_user + ';' + request + '\n';
    fs.appendFile('../certs.txt', write, function(err) {
      if (err)
        throw err;
    });
    
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
  }
});

// Função que cria o ficheiro de configuração para emissão de um pedido de novo certificado
async function create_config(country, orgname, fqdn){
  var content = 'FQDN = '+fqdn+'\\n\
ORGNAME = '+orgname+'\\n\
ALTNAMES = DNS:$FQDN\\n\
[ req ]\\n\
default_bits = 2048\\n\
default_md = sha256\\n\
prompt = no\\n\
encrypt_key = no\\n\
distinguished_name = dn\\n\
req_extensions = req_ext\\n\
[ dn ]\\n\
C = '+country+'\\n\
O = $ORGNAME\\n\
CN = $FQDN\\n\
[ req_ext ]\\n\
subjectAltName = $ALTNAMES';
  var comando = 'echo $\'' + content + '\' > serv.cnf';
  console.log(comando);
  exec(comando, {encoding: 'utf-8'});
}




router.post('/ocsp', async (req, res, next) => {
  var cert = req.body.cert1;

  if(!validate_input(cert)){
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
      var b = await check_user_cert(cert);
      if(!b){
        alert('Certificate not found!');
      }
      else{
        comando = 'sudo openssl ocsp -CAfile /root/ca/cacert.pem -issuer /root/ca/cacert.pem -cert /root/ca/certs/'+cert+'.crt -url http://127.0.0.1:8080/ -resp_text -noverify > ./ocsp.txt';
        console.log(comando);
        exec(comando, { encoding: 'utf-8' });
        setTimeout(function(){exec('xdg-open ocsp.txt', {encoding:'utf-8'})}, 5000);
      }
  }


  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
});




router.post('/crl', async (req, res, next) => {
  var cert = req.body.cert0;

  if(!validate_input(cert)){
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
      var b = await check_user_cert(cert);
      if(!b){
        alert('Certificate not found!');
      }
      else{
        comando = 'sudo openssl verify -extended_crl -verbose -CAfile /root/ca/crl/test.pem -crl_check /root/ca/certs/'+cert+'.crt > ./crl.txt';
        console.log(comando);
        exec(comando, { encoding: 'utf-8' });
        setTimeout(function(){exec('xdg-open crl.txt', {encoding:'utf-8'})}, 5000);
      }
  }


  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
});





// Aqui alterar webserver para um certificado do utilizador 
router.post('/timestamp', async (req, res, next) => {
  var ts = req.body.ts;
  var cert = req.body.cert3;
  if(!(validate_input(cert) && validate_input(ts))){
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
    var b = await check_user_cert(cert);
    if(!b){
      alert('Certificate not found!');
    }
    else{
      comando = 'sudo openssl ts -query -data /root/ca/certs/'+cert+'.crt -out /root/ca/timestamp/'+ts+'.tsq';
      console.log(comando);
      exec(comando, { encoding: 'utf-8' });

      // regista em 'timestamps.txt' a que utilizador corresponde o novo pedido de timestamp
      var write = logged_user + ';' + ts + '\n';
      fs.appendFile('../timestamps.txt', write, function(err) {
        if (err)
          throw err;
      });
    }
  }


  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
})


router.post('/timestampcheck', async (req, res, next) => {
  var cert = req.body.cert4;
  if(!validate_input(cert)){
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }
  else{
    var b = await check_user_timestamp(cert);
    console.log(b);
    if(!b){
      alert('Timestamp não consta nos seus certificados!');
    }
    else{
      comando = 'sudo openssl ts -verify -queryfile /root/ca/timestamp/'+cert+'.tsq -in /root/ca/timestamp/'+cert+'.tsr -CAfile /root/ca/cacert.pem -untrusted /root/ca/timestamp/tsa.pem >> ./timestamp.txt';
      console.log(comando);
      exec(comando, { encoding: 'utf-8' });
      setTimeout(function () {data = fs.readFileSync('./timestamp.txt', 'utf8');alert(data.split('\n')[data.split('\n').length-2]);}, 3000);      
    }
  }
  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
})



async function check_user_timestamp(timestamp){
  data = fs.readFileSync('../timestamps.txt', 'utf8')
  
  var lines = data.split('\n');
  for(let i = 0; i < lines.length-1; i++){
      var us_cert = lines[i].split(';');
      if(us_cert[0] == logged_user && us_cert[1] == timestamp){
        //console.log('ok');
        return true;
      }
  }
  return false;
}

async function check_user_cert(certificate){
  data = fs.readFileSync('../certs.txt', 'utf8')
  
  var lines = data.split('\n');
  for(let i = 0; i < lines.length-1; i++){
      var us_cert = lines[i].split(';');
      if(us_cert[0] == logged_user && us_cert[1] == certificate){
        //console.log('ok');
        return true;
      }
  }
  return false;
}



router.post('/mycertificates', async (req, res, next) => {
  x = await my_certificates();
  alert(x);
  z = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(z);
})


async function my_certificates(){
  data = fs.readFileSync('../certs.txt', 'utf8');
  lines = data.split('\n');
  res = 'Your certificates: ';
  for(let i = 0; i < lines.length-1; i++){
    us_cert = lines[i].split(';');
    if(us_cert[0] == logged_user){
      res = res + '\n' + us_cert[1];
    }
  }
  return res;
}


router.post('/viewcertificate', async (req, res, next) => {
  cert = req.body.viewcert;
  if(!validate_input(cert)){
    x = __dirname.split('/routes')[0] + '/views/home.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }
  else{
      var b = await check_user_cert(cert);
      if(!b){
        alert('Certificate not found!');
      }
      else{
        exec('sudo xdg-open /root/ca/certs/'+cert+'.crt', {encoding:'utf-8'});
      }
  }
  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
})



//router.post('/logout', async (req, res, next) => {
//  logged_user = '';
//  x = __dirname.split('/routes')[0] + '/views/login.html';
//  res.sendFile(x);
//})



module.exports = router;
















/*

router.post('/mycertificates', async (req, res, next) => {

  var username = req.body.username3;
  var password = req.body.password3;
  var j = 0;
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
        
        //console.log(res.data.total);
        for(j = 0; j < res.data.total; j++){
          var us_cert = lines[i].split(';');
          if(us_cert[0] == username && us_cert[1] == res.data.entries[j].id){
            console.log(res.data.entries[j]);
          }
        } j=0;
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
  if(!login_aux(username, password, dt) == false){
    console.log('Auth error');
    return;
  }

  //setTimeout(function(){ console.log("timeout"); }, 3000);

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






router.post('/newcertificatesignedocsp', (req, res, next) => {
  var dat = {
    "Attributes": [],
    "ProfileID": "caOCSPCert",
    "Renewal": "false",
    "RemoteHost": [],
    "RemoteAddress": [],
    "Input": [
       {
          "@id": "i1",
          "ClassID": "certReqInputImpl",
          "Name": "Certificate Request Input",
          "Attribute": [
             {
                "@name": "cert_request_type",
                "Value": "pkcs10",
                "Descriptor": {
                   "Syntax": "cert_request_type",
                   "Description": "Certificate Request Type"
                }
             },
             {
                "@name": "cert_request",
                "Value": "-----BEGIN CERTIFICATE REQUEST----- MIICkjCCAXoCAQAwTTEQMA4GA1UECgwHRVhBTVBMRTETMBEGA1UECwwKcGtpLXRvbWNhdDEkMCIG A1UEAwwbQ0EgT0NTUCBTaWduaW5nIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A MIIBCgKCAQEA0U/2nGfi1pcX2laCadTzBZf+BIs+Ny50b0bLM3NQud/8YDr0R46WTDcHm/7cgkBI VpyibFEfuWF52REHL7mJxW5zAmi2mml4+niRSDnY1YoBmOjHecPYVH7deECnlIFTGsQW5q9fLvsx BGWNNo953u3G3SsweQw21dAxl84EnFO9wJS9OW5OQUj1RAZu2U2vaHYtO3E9EkxGa/1bhhUMFPoL RlyGrHbMScOMrQ/nC7Id+cxrJQlC7lOi5f14/2jUzRL3MRBI5E/26kd0uHtmO1MhjkeXj1qB6Vdo Ua+igC0Me/XNdm68YzCAYp0QhT+CNn5dy2jMU44FwDZzqxa8/wIDAQABoAAwDQYJKoZIhvcNAQEL BQADggEBAE2JGtFTWsa8lkq4BaWqoQjNLmhJNAORSOgsRAETPnHa3bIOvFb+fRojIPaDc1bOpnA2 sVMXgMjEaho9DfWCFYYHT+pkA0A9iIWQ6FIKGhjPhPJiLGZNoVqiaaXoOY8FJRu3YZfrMrtGJWtK NUMedbNACKiqsKj54aV+m0nInOb3qKXZBprjMYoktESvGYKSLH5EkGLEiPs9zU/2wmwGXX8W+Y+Q 6Cayb+/IBRMqINGXE2cUpaCUSWm3HJTA08YAAz67VihP+xJB+OJ2o81eKFMfcBSS23cr75VXQLsl K1j29/7tMaPCx5J6nyJq+Woi6D9GNFCGl+GuI/Bv7lZHpaM= -----END CERTIFICATE REQUEST----- ",
                "Descriptor": {
                   "Syntax": "cert_request",
                   "Description": "Certificate Request"
                }
             }
          ]
       },
       {
          "@id": "i2",
          "ClassID": "submitterInfoInputImpl",
          "Name": "Requestor Information",
          "Attribute": [
             {
                "@name": "requestor_name",
                "Value": "1",
                "Descriptor": {
                   "Syntax": "string",
                   "Description": "Requestor Name"
                }
             },
             {
                "@name": "requestor_email",
                "Value": "1",
                "Descriptor": {
                   "Syntax": "string",
                   "Description": "Requestor Email"
                }
             },
             {
                "@name": "requestor_phone",
                "Value": "1",
                "Descriptor": {
                   "Syntax": "string",
                   "Description": "Requestor Phone"
                }
             }
          ]
       }
    ]
 };


  var username = req.body.username5;
  var password = req.body.password5;
  var dt = fs.readFileSync('../users.txt', 'utf8');
  console.log(username);
  console.log(password);
  if(!login_aux(username, password, dt)){
    console.log('Auth error');
    return;
  }


  setTimeout(function(){ console.log("timeout"); }, 3000);


  console.log('aqui1');
  axios.post('https://fedora:8443/ca/rest/certrequests/', dat).then( (res) => {
    console.log('aqui2')
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





router.post('/crl', async (req, res, next) => {
  var cert = req.body.cert0;
  var r = 0;
  console.log(cert);
  var boo = false;
  axios.get('https://fedora:8443/ca/rest/certs').then( (res) => {
    for(let i=0; i < res.data.entries.length; i++){
      if(res.data.entries[i].Status == 'REVOKED'){
        fs.appendFile('../crl.txt', res.data.entries[i].id + '\n', function(err){
            if(err) throw err;            
        });
      }
      else {if(i==res.data.entries.length-1) auxiliar(cert);}
    }
  });
  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
});


async function auxiliar(cert){
  var boo = false;
  cert = '0x' + parseInt(cert).toString(16);
  fs.readFile('../crl.txt', 'utf8', (err, data) => {
    if(err) throw err;
    d = data.split('\n');
    for(let i = 0; i < d.length; i++){
      if(cert == d[i]) boo = true;
    }
    if(boo) alert('REVOKED');
    else alert('VALID');
  });
}



router.post('/ocsp', (req, res, next) => {
  var cert = req.body.cert1;
  var link = 'https://fedora:8443/ca/rest/certs/' + cert;
  axios.get(link).then( (res) => {
      alert(res.data.Status);
  });
  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
});


*/



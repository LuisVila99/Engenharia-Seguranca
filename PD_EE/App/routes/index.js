/*********************\
 * VARIÁVEIS GLOBAIS *
\*********************/

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


/*********************\
 * VALIDAÇÃO DE INPUT *
\*********************/

// Função que servirá para validação de input, verificando se algum caracter do input não pertence à lista de caracteres permitidos
function validate_input(input){
  for(let i = 0; i < input.length; i++){
    if(!whitelist.includes(input[i])) return false;
  }
  return true;
}


/*****************************\
 * FUNCIONALIDADES APLICAÇÃO *
\*****************************/



/* GET home page. 
 * Carrega o HTML da página inicial ao lançar a aplicação
 */
router.get('/', function(req, res, next) {
  x = __dirname.split('/routes')[0] + '/views/login.html';
  res.sendFile(x);
});


/* Registo de um utilizador 
 * Recebido input com o novo username e com a password para registo.
 * Os inputs são validados.
 * Verifica-se se o nome de utilizador já foi utilizado.
 * É registado o novo utilizador.
 */
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



/* Login na aplicação. 
 * Recebe o username e password como input.
 * Valida os inputs.
 * Verifica se o username existe e se a password inserida é a correta.
 * Sendo o login bem-sucedido é carregada a página inicial da aplicação.
 */
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

/* Auxiliar ao login. 
 * Verifica se um nome de utilizador e respetiva password se encontram no ficheiro onde estes são guardados.
 */
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


/* Ação de clicar no botão de novo certificado. 
 * Carrega a página onde se preenchem as informações para pedido de novo certificado.
 */
router.post('/newcertificate', async (req, res, next) => {  
    try {
      y = __dirname.split('/routes')[0] + '/views/newcert.html'; 
      res.sendFile(y);
    } catch (error) {
        throw error;
    }
});


/* Emissão de novo pedido de certificado.
 * São recebidas por input as informações necessárias para emissão de um novo certificado.
 * Os inputs são validados.
 * Cria-se um ficheiro de configuração que especifica com que informações será criado o novo certificado.
 * Cria-se um certificate request com recurso a esse ficheiro e a um comando do OpenSSL.
 */
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

/* Auxiliar à emissão de um certificate reqquest. 
 * Função que cria o ficheiro de configuração para emissão de um pedido de novo certificado.
 */
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



/* Verificação do estado de um certificado por OCSP. 
 * Recebe como input qual o certificado sobre o qual ocorrerá a verificação.
 * O input é validado.
 * Verifica-se que o certificado pertence ao utilizador que faz o pedido de verificação.
 * A verificação é efetuada através de um comando do OpenSSL.
 * O seu resultado é guardado num ficheiro que é posteriormente aberto para o utilizador.
 */
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




/* Verificação do estado de um certificado por CRL. 
 * Recebe como input qual o certificado sobre o qual ocorrerá a verificação.
 * O input é validado.
 * Verifica-se que o certificado pertence ao utilizador que faz o pedido de verificação.
 * A verificação é efetuada através de um comando do OpenSSL.
 * O seu resultado é guardado num ficheiro que é posteriormente aberto para o utilizador.
 */
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
        exec('openssl ca -gencrl -keyfile /root/ca/private/cakey.pem -cert /root/ca/cacert.pem -out /root/ca/crl/crl.pem', { encoding: 'utf-8' });
        exec('cat /root/ca/cacert.pem /root/ca/crl/crl.pem > /root/ca/crl/test.pem', { encoding: 'utf-8' });
        comando = 'sudo openssl verify -extended_crl -verbose -CAfile /root/ca/crl/test.pem -crl_check /root/ca/certs/'+cert+'.crt > ./crl.txt';
        console.log(comando);
        exec(comando, { encoding: 'utf-8' });
        setTimeout(function(){exec('xdg-open crl.txt', {encoding:'utf-8'})}, 5000);
      }
  }


  x = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(x);
});





/* Pedido de timestamp sobre um certificado.
 * Recebe-se como input qual o certificado sobre o qual se quer o timestamp e qual o nome para o timestamp.
 * Os inputs são validados.
 * Verifica-se que o certificado pertence ao utilizador que pede o timestamp.
 * É criado um pedido de timestamp através de um comando de OpenSSL.
 */
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


/* Verificar timestamp. 
 * Recebe como input qual o timestamp sobre o qual ocorrerá a verificação.
 * O input é validado.
 * Verifica-se que o timestamp pertence ao utilizador que faz o pedido de verificação.
 * A verificação é efetuada através de um comando do OpenSSL.
 * O seu resultado é guardado num ficheiro cuja informação é lida e passada ao utilizador por um alerta.
 */
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
      alert('Timestamp não consta nos seus timestamps!');
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


/* Função auxiliar que verifica se um timestamp pertence ao utilizador ligado à aplicação num determinado momento.
 */
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

/* Função auxiliar que verifica se um certificado pertence ao utilizador ligado à aplicação num determinado momento.
 */
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


/* Mostra a um utilizador quais são os seus certificados (pedidos e já aceites).
 */
router.post('/mycertificates', async (req, res, next) => {
  x = await my_certificates();
  alert(x);
  z = __dirname.split('/routes')[0] + '/views/home.html';
  res.sendFile(z);
})


/* Função auxiliar que verifica quais os certificados do utilizador a usar a aplicação num determinado momento.
 */
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

/* Ver um certificado
 * Utilizador indica qual o certificado que pretende ver.
 * input é validado e verifica-se que o certificado pertence ao utilizador que pediu para o ver.
 * É mostrado o conteúdo do certificado ao utilizador.
 */
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








/*********\
 * ADMIN *
\*********/

/* Aceitar um certificate request.
 * É dado como input o nome do request.
 * Valida-se o input.
 * Request é aceite e novo certificado criado com o mesmo nome por comando OpenSSL.
 */
router.post('/acceptcertificate', async (req, res, next) => {
  var cert = req.body.cert_to_accept;
  if(!validate_input(cert)){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/admin.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
    com = 'sudo openssl ca -batch -in /root/ca/requests/'+cert+'.csr -out /root/ca/certs/'+cert+'.crt';
    console.log(com);
    exec(com, { encoding: 'utf-8' });
  }
  x = __dirname.split('/routes')[0] + '/views/admin.html';
  res.sendFile(x);
})



/* Revocar um certificado.
 * É dado como input o nome do certificado.
 * Valida-se o input.
 * Certificado é revocado por comando OpenSSL.
 */
router.post('/revokecertificate', async (req, res, next) => {
  var cert = req.body.cert_to_revoke;
  if(!validate_input(cert)){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/admin.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
    com = 'sudo openssl ca -revoke /root/ca/certs/'+cert+'.crt -keyfile /root/ca/private/cakey.pem -cert /root/ca/cacert.pem ';
    console.log(com);
    exec(com, { encoding: 'utf-8' });
  }
  x = __dirname.split('/routes')[0] + '/views/admin.html';
  res.sendFile(x);
})



/* Aceitar um timestamp request.
 * É dado como input o nome do request.
 * Valida-se o input.
 * Request é aceite e novo timestamp criado com o mesmo nome por comando OpenSSL.
 */
router.post('/accepttimestamp', async (req, res, next) => {
  var cert = req.body.time_to_accept;
  if(!validate_input(cert)){ // validação dos inputs recebidos 
    x = __dirname.split('/routes')[0] + '/views/admin.html';
    res.sendFile(x);
    alert('Input com caracteres inválidos!')
    return;
  }else{
    com = 'sudo openssl ts -reply -queryfile /root/ca/timestamp/'+cert+'.tsq -out /root/ca/timestamp/'+cert+'.tsr';
    console.log(com);
    exec(com, { encoding: 'utf-8' });
  }
  x = __dirname.split('/routes')[0] + '/views/admin.html';
  res.sendFile(x);
})



module.exports = router;
#AUTH
Simple authentication service for handling passwords and tokens for REST API.

##Quick Start
AUTH is super simple to use and takes the science and math out of secuity in Node.js. 
Lets show how to use the module.



**Encrypt Password**

```
const salt = '10';  //number used by algorithm to encrypt passowrd (higher more cpu usage)
const secret = 'ASDF292323WE23WED'; //encrypted message to ensure from this server
const auth = require('auth')(salt,secret);

const password = 'Some secret';
const encryptedPassword = auth.encrypt(password);

//save password in your database or storage model (mongodb,mysql,redis)

//give user a token so they dont have login everytime (see below)
```

**Check Password**

```
const salt = '10';  //number used by algorithm to encrypt passowrd (higher more cpu usage)
const secret = 'ASDF292323WE23WED'; //encrypted message to ensure from this server
const auth = require('auth')(salt,secret);
const password = 'Some secret';

if(auth.passwordIsGood(password)){
 //password is good, grant access
}else{
//password is bad, deny-access
}
```


**Create API token**

```
const salt = '10';  //number used by algorithm to encrypt passowrd (higher more cpu usage)
const secret = 'ASDF292323WE23WED'; //encrypted message to ensure from this server
const auth = require('auth')(salt,secret);

const info = 'some string data'; //data to save inside token
const moreInfo = JSON.strigify({data : some string data}); //if object, make string first
const time = '1 year'; //time to save token, can also be in milliseconds

const token = auth.generateToken(info,time);
```

** Validate API Token **
```
const salt = '10';  //number used by algorithm to encrypt passowrd (higher more cpu usage)
const secret = 'ASDF292323WE23WED'; //encrypted message to ensure from this server
const auth = require('auth')(salt,secret);
const token = 'hash junk'; //token pulled from api request

if(auth.tokenIsGood){
//token is good, grant access
}{
//token is bad, redirect to login
}
```

** Get information From Token **
NOTE: The method only works with tokens generated by your server!

```
const salt = '10';  //number used by algorithm to encrypt passowrd (higher more cpu usage)
const secret = 'ASDF292323WE23WED'; //encrypted message to ensure from this server
const auth = require('auth')(salt,secret);
const token = 'hash junk'; //token pulled from api request

var info = auth.getInfo(token);

if(token){

//get information from inside, if you saved an object, parse

}

```



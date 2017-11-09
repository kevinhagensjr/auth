const debug = require('debug')('demio:Auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

class Auth{
	
	constructor(salt){
		
		this.secret = salt;
		this.saltRounds = 10;
	}
	
	/*
		@params - info - data to save inside token
		@params - time - time in miliseconds token is valid
		Description: generates a json web token for user
	*/
	generateToken(info, time){
		
		if(!info){
			
			debug('ERROR, info is empty!');
			return false;
		}
		
		if(time && time <= 0){
			
			debug('ERROR, time must be greater than zero');
			return false;
		}
		
		return jwt.sign({ data : info}, this.secret, { expiresIn: time}); //TO DO: connect with CA 
	}
	
	/*
		@params - req - the http request headers/body
		Description: checks a web token to see if corrupt	
	*/
	tokenIsGood(token){
		
		if(!token || token  > 10){
			
			debug('ERROR, not a valid token!');
			return false;
		}
		
		try{
			
			jwt.verify(token,this.secret);
			return true;
			
		}catch(e){
			
			if(err){
				
				//TO DO: Block ip address if too many failed attempts
				debug('ERROR, token is in valid, either expired or corrupted!');
				return false;
			}
		}
	}
	
	/*
		@params - req - request headers 
		Description: gets info authorization header
	*/
	getInfo(token){
		
		if(!tokenIsGood(token)){
			return false;
		}
		
		const decodedToken = jwt.decode(token);	
		const info = decodedToken.data;
		
		if(info)
			return info;
		else{
			
			debug('ERROR, token data is empty!');
			return false;	
		} 
	}
	
	/*
		@params - password - new / updated password for user
		Description: one way encryption for user password	
	*/
	encrypt(password){
		
		return bcrypt.hashSync(password, this.saltRounds); //TO DO: switch to async
	}
	
	/*
		@params - req - the http request headers/body
		Description: checks a web token to see if corrupt	
	*/
	passwordIsGood(password){
		
		return bcrypt.compareSync(password, hash); //TO DO: switch to async
	}
}

module.exports = new Auth();
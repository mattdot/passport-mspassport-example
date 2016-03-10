var bcrypt = require("bcrypt-nodejs");
var crypto = require("crypto");

var UserDB = function(data) {
    this.users = {};
    if(Array.isArray(data)) {
        for(var u in data) {
            this.add(data[u]);
         }
    }
};

UserDB.prototype.findByUserPassword = function(username, password, callback) {
    if (this.users.hasOwnProperty(username)) {
        var user = this.users[username];
        if(user && bcrypt.compareSync(password, user.credentials.password)) {
            //valid user
            return callback(null, user);
        }
    }
    
    return callback(null, false);
};

UserDB.prototype.findByPublicKey = function(pk, callback) {
    for (var id in this.users) {
        if (this.users.hasOwnProperty(id)) {
            var user = this.users[id];
            
            for (var key in user.credentials.keys) {
                if(key === pk) {
                    return callback(null, user);  
                };
            }
        }
    }
    
    return callback(null, false); //not found
};

UserDB.prototype.findByToken = function(token, callback) {
    for (var id in this.users) {
        if (this.users.hasOwnProperty(id)) {
            var user = this.users[id];
            
            for (var t in user.credentials.tokens) {
                if(t === token) {
                    return callback(null, user);  
                };
            }
        }
    }
    
    return callback(null, false); //not found
};

UserDB.prototype.add = function(user) {
	console.log(user);
    if(user.credentials.hasOwnProperty('password') && user.credentials.password.length > 0) {
        user.credentials.password = bcrypt.hashSync(user.credentials.password);
    }
    
    this.users[user.preferredUserName] = user;
};

UserDB.prototype.generateToken = function(username) {
    var token = { token : crypto.randomBytes(16).toString('hex'), expires : new Date() };  
    if (this.users.hasOwnProperty(username)) {
        var user = this.users[username];
        if(user) {
            if(!user.credentials.tokens) {
                user.credentials.tokens = [];
            }
            
            user.credentials.tokens.push(token);
            
            return token;
        }
    }
    
    return null;
};

module.exports = UserDB;

var express = require("express");
var bodyParser = require('body-parser');
var passport = require("passport");
var mspassport = require("passport-mspassport");
var basic = require("passport-http");
var bearer = require("passport-http-bearer");
var bcrypt = require("bcrypt-nodejs");
var crypto = require("crypto");

var UserDB = require("./users");
var MSPassportStrategy = mspassport.Strategy;
var BasicStrategy = basic.BasicStrategy;
var BearerStrategy = bearer.Strategy;

// a simple in-memory db of users.  For example only, 
// use a real database to store your data!
var users = new UserDB([
    {
        "preferredUserName" : "mattdot",
        "displayName" : "Matt Dotson",
        "credentials" : {
            "password" : "secret",
            "keys" : ["1234567890"]
        }
    }
]);

var app = express();
app.use(express.static('static'));
app.use(bodyParser.json());

// configure passport to use the MSPassportStrategy
passport.use("mspassport", new MSPassportStrategy({
    protocol: "http-auth-header",
    findUserByPublicKey: function (key, done) {
        return users.findByPublicKey(key, function(user) {
            done({
                "id" : user.id,
                "displayName" : user.displayName,
                "preferredUserName" : user.preferredUserName
            });
        });
    }
}));

passport.use(new BasicStrategy(function(username, password, done) {
    console.log(password);
    users.findByUserPassword(username, password, done);
}));

passport.use(new BearerStrategy(users.findByToken));



app.get("/api/v1/me", passport.authorize('bearer', { session: false }), function (req, res) {
    res.json(req.user);
});

app.put("/api/v1/me/keys", passport.authorize('bearer', { session: false }), function (req, res) {
    
});

/*
 *
 * 
 */
app.post('/api/v1/me/logout', passport.authorize('bearer', { session: false }), function(req, res){
   req.logout(); 
});


/*
 *
 * 
 */
app.put("/register", function(req, res) {
    users.add(req.body);
    res.json(req.body);
    req.login(req.body);
});

/*
 *
 * 
 */
app.get("/auth/password", passport.authorize("basic", { session: false }), function (req, res) {
    var token = users.generateToken(req.user.preferredUserName);
    res.json(token);
});

/*
 *
 * 
 */
app.get("/auth/mspassport", passport.authorize("mspassport", { session: false }), function (req, res) {
    var token = users.generateToken(req.user.preferredUserName);
    res.json(token);
});


var port = process.env.PORT || 1339;
app.listen(port, function() {
    console.log("listening for requests on port %d", port);
});
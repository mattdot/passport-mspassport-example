var express = require("express");
var bodyParser = require('body-parser');
var passport = require("passport");
var mspassport = require("passport-mspassport");
var basic = require("passport-http");
var bcrypt = require("bcrypt-nodejs");
var crypto = require("crypto");

var UserDB = require("./users");
var MSPassportStrategy = mspassport.Strategy;
var BasicStrategy = basic.BasicStrategy;

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
// app.use(function(req, res, next){
//     //redirect to https if not on development
//     if((/localhost/i).test(req.headers.host)) {
//         if(req.secure) {
//             next();
//         } else {
//             res.redirect("https://" + req.headers.host + req.url);
//         }
//     }
// });
app.use(express.static('static'));
app.use(bodyParser.json());

// configure passport to use the MSPassportStrategy
passport.use("mspassport", new MSPassportStrategy({
    protocol: "http-auth-header",
    findUserByPublicKey: function (key, callback) {
        users.findByPublicKey(key, function(user) {
            callback({
                "id" : user.id,
                "displayName" : user.displayName,
                "preferredUserName" : user.preferredUserName
            });
        });
    }
}));

passport.use(new BasicStrategy(UserDB.findByUserPassword));

/*
 *
 * 
 */
app.put("/register", function(req, res) {
    UserDB.add(req.body);
    res.json(req.body);
    req.login(req.body);
});

app.get("/api/v1/me", passport.authorize('bearer', { session: false }), function (req, res) {
    
});

app.put("/api/v1/me/keys", passport.authorize('bearer', { session: false }), function (req, res) {
    
});

/*
 *
 * 
 */
app.post('/logout', function(req, res){
   req.logout(); 
});

/*
 *
 * 
 */
app.get("/auth/password", passport.authorize("basic", { session: false }), function (req, res) {
    var token = UserDB.generateToken(req.user.preferredUserName);
    res.json(token);
});

app.get("/auth/mspassport", passport.authorize("mspassport", { session: false }), function (req, res) {
    var token = UserDB.generateToken(req.user.preferredUserName);
    res.json(token);
});

var port = process.env.PORT || 1339;
app.listen(port, function() {
    console.log("listening for requests on port %d", port);
})
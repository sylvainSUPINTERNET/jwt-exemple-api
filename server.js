'use strict';

// =======================
// get the packages we need ============
// =======================
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');

const sha256 = require('sha256');

//call API
var querystring = require('querystring');
var http = require('http').Server(app);
const http_ = require('http');
const http_request = require('http');

var request = require('request');




var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
const cookieParser = require('cookie-parser');
app.use(cookieParser());

var config = require('./config'); // get our config file (mongoDB)

var User = require('./app/models/user'); // get our mongoose model

var random = require('./app/utils/random'); //methods annexes

// =======================
// configuration =========
// =======================
var port = process.env.PORT || 8000; // used to create, sign, and verify tokens

app.set('superSecret', config.secret); // secret variable  //variable environnement app.get('superSecret');
mongoose.connect(config.database); // connect to database

app.set('view engine', 'ejs');


// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// =======================
// routes ================
// =======================

//Register
app.post('/register', function (req, res, next) {

    let errors = {
        name: "",
        password: "",
        passwordConfirmed: ""
    };


    let name = String(req.body.name);
    let password = String(req.body.password);
    let passwordConfirmed = String(req.body.passwordConfirmed);


    if (name.length <= 3 || typeof name !== 'string') {
        errors.name += "Votre nom doit faire minimum 3 caractères !";
    }
    if (password.length <= 3 || typeof password !== 'string') {
        errors.password += "Votre nom doit faire minimum 3 caractères !";
    }

    if (passwordConfirmed.length <= 3 || typeof passwordConfirmed !== 'string' || passwordConfirmed !== password) {
        errors.passwordConfirmed += "Vos mots de passe doivent correspondre !";
    }


    if (errors.name === "" && errors.password === "" && errors.passwordConfirmed === "") {
        //IF SUCCESS ON INSERT

        let salt = random(10);
        let hashPassword = sha256(password + salt);


        var userToCreate = new User({
            name: name,
            password: hashPassword,
            salt: salt
        });

        userToCreate.save(function (err) {
            if (err)
                throw err;

            // create a token
            var token = jwt.sign({"name": userToCreate.name, "password": userToCreate.password}, app.get('superSecret'), {
                expiresIn: "1d" // d h etc
            });

            res.cookie('token', token);
            res.json({user: userToCreate})
        });




    } else {
        //MINIMUM une erreur / 3
        res.json(errors);
    }

});

app.get('/register', function (req, res, next) {
    res.render('register', { path_name : '/register' });
});




//Login
app.get('/login', function (req, res) {
    res.render('login', { path_name : '/login' });
});

app.post('/login', function (req, res) { // /api/login POST => name / password
    // find the user
    User.findOne({
        name: req.body.name
    }, function (err, user) {

        if (err) throw err;

        if (!user) {
            res.json({success: false, message: 'Login failed. User not found.'});
            //console.log(user);
            //redirect to inscription page
        } else if (user) {
            // check if password matches
            if (user.password != sha256(req.body.password + user.salt)) {
                res.json({success: false, message: 'Login failed. Wrong password.'});
            } else {

                // if user is found and password is right
                // create a token
                // ON PEUT AJOUTER DES CHAMPS ICI qui seront accessible ensuite dans le verify via decode()(format json)
                var token = jwt.sign({"name": user.name, "password": user.password}, app.get('superSecret'), {
                    expiresIn: "1d" // d h etc
                });

                res.cookie('token', token);
                res.json({
                    success: true,
                    message: 'Enjoy your token!',
                    token: token
                });
            }

        }

    });
});

app.get('/logout', function(req,res){

	res.clearCookie("token"); //delete token => deconnexion
	let path_name = '/login'; //redirect
	
    res.render('login', { path_name : '/login' });
});


// =======================
// API - CALL    =========
// =======================


app.get('/users', function (req, res, next) {
    var options = {
        host: 'localhost',
        port: 8080,
        path: "/api/users",
        json: true,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }

    };

    /*
    var post_data = querystring.stringify({
        cookies: req.cookies //req.cookies.token
    });
    */


    var post_data = req.cookies.token;


    var callback = function(response) {
        var str = ''
        response.on('data', function (chunk) {
            str += chunk;
        });

        response.on('end', function () {
            console.log("DONNE RECU " + str);
            res.json(str);
        });
    };


    var stmt = http_.request(options, callback);

    //data to post -json format
    stmt.write(`{
        "token": "${post_data}"
    }`);
    stmt.end();

});



// STORE TOKEN DANS LE HEADER x-access-token
// =======================
// SECURITY FOR EACH API ROUTES with JWT (used api side) =========
// =======================
// route middleware to verify a token
function checkToken(myToken, req, res, next, callback) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.token;

    var response_data = {
        message: "",
        error: ""
    };

    // decode token
    if (token) {
        // verifies secret and checks exp
        jwt.verify(token, app.get('superSecret'), function (err, decoded) {
            if (err) {
                response_data = {message: err, error: true};
                callback(response_data);
            } else {
                // if everything is good, save to request for use in other routes
                req.decoded = decoded; //get all data passé lors de la création du jwt (encodé avant) qui ici sont décodé en objet json
                response_data = {message: token, error: false, user_decoded_from_jwt:decoded};
                callback(response_data);
            }
        });

    } else {
        console.log("Pas de token");
        // if there is no token
        // return an error
        response_data = {message: "No token provided !", error: true};
        callback(response_data);

    }

}


// =======================
// start the server ======
// =======================
app.listen(port);
console.log('Magic happens at http://localhost:' + port);
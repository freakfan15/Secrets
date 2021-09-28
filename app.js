//jshint esversion:6
require("dotenv").config(); //for storing secret keys in env variables
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate")

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));;
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended:true}));

// ****************Setting up express sessions**********************
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}));

//*******************Setting up passport to initialise the session************************ */
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//********Using passport-local-mongoose for hashing and salting the passowrds in db************************** */
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//*************************************************************************************************** */

const User = new mongoose.model("User", userSchema);

// ******************************using passport-local-mongoose to serialise and desirialise sessions******************************
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
//****************************************************************************************************************************** */

//****************************************Google Authentication************************************************** */
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
})

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
});

app.get("/login", function(req, res){
    res.render("login");
})

app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
})

app.get("/register", function(req, res){
    res.render("register");
})

app.get("/secrets", function(req, res){
    User.find({secret: {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }
        else{
            console.log(foundUsers);
            if(foundUsers){
                console.log(foundUsers);
                res.render("secrets", {usersWithSecret: foundUsers});
            }
        }
    });
})

app.post("/register", function(req, res){
    res.render("register");
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
    
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    console.log(req.user.id);
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("secrets");
                })
            }
        }
    });
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
})


app.listen(3000, function(){
    console.log("Server started on port 3000");
})





//*********************************************************------------NOTES---------------------*****************************************************************************

//*************************Modules *********************************8 */
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

//********Encrypting using a secret key*****************************
// const secret = process.env.SECRET;
// userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});

//********************using md5 is pretty simple, check doc********************************** */

//**************************Using bcrypt for hashing and salting*******************************/

// app.post("/login", function(req, res){
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: username}, function(err, foundUser){
//         if(err){
//             console.log(err);
//         }
//         else{
//             if(foundUser){
//                 bcrypt.compare(password, foundUser.password, function(err, result){
//                     if(err){
//                         console.log(err);
//                     }
//                     else{
//                         if(result===true){
//                             res.render("secrets")
//                         }
//                     }
//                 })
//             }
//         }
//     })
// })

// app.post("/register", function(req, res){

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash){
//         if(err){
//             console.log(err);
//         }
//         else{
//             const newUser = new User({
//                 email: req.body.username,
//                 password: hash
//             })
        
//             newUser.save(function(err){
//                 if(err){
//                     console.log(err);
//                 }
//                 else{
//                     res.render("secrets");
//                 }
//             })
//         }
//     })
    
// });




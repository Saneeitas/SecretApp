/** @format */
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const _ = require("lodash");
const mongoose = require("mongoose");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
//const encrypt = require("mongoose-encryption");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook");

const app = express();

app.set("view engine", "ejs");
app.use(express.static(`${__dirname}/public`));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "my little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", true);
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {
// secret: process.env.SECRET,
// encryptedFields: ["password"],
// });

// console.log(md5(1))
// console.log(md5(1))

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//Save user id in cookie//Delete user id in cokie
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//GOOGLE
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//FACEBOOK
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

//GOOGLE STRATEGY
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//FACEBOOK STRATEGY
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/oauth2/redirect/facebook",
      state: true,
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

//FACEBOOK AUTH
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/oauth2/redirect/facebook",
  passport.authenticate("facebook", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//GOOGLE AUTH
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/auth", (req, res) => {
  if (req.isAuthenticated()) {
    res.send("Auth");
  } else {
    res.send("Not Auth");
  }
});

app.get("/secrets", (req, res) => {
  User.find({ "secret": { $ne: null } }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers})
      }
    }
  })
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
          
        });
      }
    }
  );
  // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
  // const newUser = new User({
  // username: req.body.username,
  // password: hash,
  // });
  // newUser.save((err) => {
  // if (err) {
  // console.log(err);
  // } else {
  // res.render("secrets");
  // }
  // });
  // });
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });

  // const username = req.body.username;
  // const password = req.body.password;
  // User.findOne({ email: username }, (err, foundUser) => {
  // if (err) {
  // console.log(err);
  // } else {
  // if (foundUser) {
  // bcrypt.compare(password, foundUser.password, (err, result) => {
  // if (result === true) {
  // res.render("secrets");
  // }
  // });
  // }
  // }
  // });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port 3000");
});

import 'dotenv/config';
import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import passport from 'passport';
import passportLocalMongoose from "passport-local-mongoose";
import {Strategy as GoogleStrategy} from "passport-google-oauth20";
import findOrCreate from "mongoose-findorcreate";


const app = express();
const port = 3000;


app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/auth/google", 
  passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  });

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/secrets", async (req, res) => {
  const foundUser = await User.find({"secret": {$ne: null}});
  try {
    if (foundUser) {
      res.render("secrets.ejs", {usersWithSecrets: foundUser})
    }
  } catch (error) {
    res.send(error);
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;

  const foundUser = await User.findById(req.user.id);
  try {
    if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save();
      res.redirect("/secrets");
    }
  } catch (error) {
    res.send(error);
  }
});

app.get("/logout", (req, res) => {
  req.logout(error => {
    if (error) {
      console.log(error);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", async (req, res) => {
  User.register({username: req.body.username}, req.body.password, (error, user) => {
    if (error) {
      res.redirect("/register");
      console.log(error);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      }) 
    }
  });
});

app.post("/login", async (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, (error) => {
    if (error) {
      console.log(error);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      })
    }
  });
});


app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
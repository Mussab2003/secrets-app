import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import 'dotenv/config'
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: process.env.DB_USER,  
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
  }
}));

app.use(passport.initialize());

app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/secrets", async(req, res) => {
  console.log(req.user);
  if(req.isAuthenticated()){
    const result = await db.query("SELECT secret FROM secret_user WHERE email = $1", [req.user.email]);
    const secret = result.rows[0].secret;
    if(secret){
      res.render('secrets.ejs', {secret : secret});
    }
    else{
      res.render('secrets.ejs', {secret : "Enter a secret"});
    }
  }
  else{
    res.redirect('/login');
  }
});

app.get("/submit", (req, res) => {
  if(req.isAuthenticated()){
    res.render('submit.ejs');
  }
  else{
    res.redirect('/login');
  }
}); 

app.post("/submit", async (req, res) => {
  if(req.isAuthenticated()){
    const secret = req.body.secret;
    console.log(secret);
    console.log(req.user.email);
    try{
      await db.query("UPDATE secret_user SET secret = $1 WHERE email = $2;", [secret, req.user.email]);
    }
    catch(err){
      console.log(err);
    }
    res.redirect('/secrets');
  }
  else{
    res.redirect('/login');
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  try{
    const result = await db.query("SELECT * FROM secret_user WHERE email = $1", [username]);
    if(result.rowCount >= 1){
      res.send("Email Already Exists.")
    }
    else{
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if(err){
          console.log(err + "Hasing Error");
        }
        const result = await db.query("INSERT INTO secret_user(email, password) VALUES($1, $2) RETURNING *;", [username, hash]);
        const user = result.rows[0];
        req.login(user, (err) => {
          console.log(err);
          res.redirect('/secrets');
        })
      });
    }
  }
  catch(err){
    console.log(err);
  }
});

app.get('/logout', (req,res) => {
  req.logout((err) => {
    if(err){
      console.log(err);
    }
    res.redirect("/");
  });
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

app.post("/login", passport.authenticate("local", {
  successRedirect : '/secrets',
  failureRedirect : '/login',
}));

passport.use("local", new Strategy(async function verifty(username, password, cb){
  try{
    const result = await db.query("SELECT * FROM secret_user WHERE email = $1", [username]);
    if(result.rowCount >= 1){
      const user = result.rows[0];
      const storedPassword = user.password;
      bcrypt.compare(password, storedPassword, (err, result) => {
        if(err){
          return cb(err);
        }
        else{
          if(result){
            return cb(null, user);
          }
          else{
            return cb(null, false);
          }
        }
      });
    }
    else{
      return cb("Incorrect Credentials");
    }
  }
  catch(err){
    return cb(err);
  }
}));

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfile: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async(accessToken, refreshToken, profile, cb) => {
  try{
    const newUser = await db.query("SELECT * FROM secret_user WHERE email=$1", [profile.email]);
    if(newUser.rowCount == 0){
      await db.query("INSERT INTO secret_user(email, password) VALUES($1, $2)", [profile.email, "google"]);
      return cb(null, newUser.rows[0]);
    }
    else{
      return cb(null, newUser.rows[0]);
    }
  }
  catch(err){
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

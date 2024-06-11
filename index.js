import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";


const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "babatunde3891",
  port: 5432,
});

// connnecting database 
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


// This allow the middleware (session) to be added 
app.use(session ({
  secret: "TOPSECRETWORD",   //an encryption key which needed to be kept secret (Pls don't push your secret in a repo)
  resave: false,
  saveUninitialized:true,
  cookie:{
    maxAge:1000 * 60 * 60 * 24, // this part help set the time limit for which the cookies can last.
  }
}))


// This line allow the usage of passport for authentication (always come after session creation)
// they are good as it keep a login session of a user in order to access a page
  app.use(passport.initialize());
  app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs");
});


app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});



// this part check if user is authenticated via passport middleware b4 taking user to required page or redirect to login page
app.get("/secrets", (req,res) => {
  console.log(req.user) // not compulsory though but u can use this line to get the result of the registered users on ur terminal
if (req.isAuthenticated()){
  res.render("secrets.ejs");
}else{
  res.redirect("/login");
}
});

// part for registering of users and adding of salt and hash function to the password
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    // Check if user with the provided email already exists
    const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkUser.rows.length > 0) {
      res.send("User already exists");
    } else {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      console.log("Hashed Password:", hashedPassword);

      // Insert the new user into the database with hashed password
      const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hashedPassword]);
      const user = result.rows[0];
      //res.render("secrets.ejs");
      req.login(user, (err)=>{
        console.log(err)
        res.redirect("/secrets")
      })
    }
  } catch (err) {
    console.error(err);
  }
});


//codes for login using passport with function authenticate that will
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));


// very important
passport.use(new Strategy( async function Verify(username,password,cb){
  console.log(username);
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      console.log(user);

    // Verify the password
    const passwordMatch = await bcrypt.compare(password, storedHashedPassword);
      if (passwordMatch) {
        //res.render("secrets.ejs");
        return cb(null, user);
      } else {
        //res.send("Incorrect password");
        return cb(null, false);
      }
    } else {
      return cb("User not found");
    }
  } catch (err) {
    console.error("Error during login:", err);
  }
})
);


// very key when working with passport session
passport.serializeUser((user,cb)=>{
cb(null,user);
});

// very key when working with passport session
passport.deserializeUser((user,cb)=>{
  cb(null,user);
  });
  

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

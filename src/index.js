require("dotenv/config");


const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const { isAuth } = require("./auth.js");
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const _ = require("lodash");
const PORT = process.env.PORT || 3000;
const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
const dateObj = new Date();

mongoose.connect(
  "mongodb+srv://test123:test9876@clustertest.d2mpq3r.mongodb.net/?retryWrites=true&w=majority",
  { useNewUrlParser: true, useUnifiedTopology: true }
);
const DataSchema = {
  first_name: String,
  last_name: String,
  email: String,
  password: String,
  Rtoken: String,
};
const userD = mongoose.model("User-Datas", DataSchema);

const {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
  sendAccessToken,
} = require("./token.js");
const res = require("express/lib/response");
const req = require("express/lib/request");

const server = express();




server.use(express.json());
server.use(express.urlencoded({ extended: true }));



// Login , Register User and Generating Refresh Token

server.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    // username chk
    let user = await userD.findOne({ email: email });

    if (!user) throw new Error("User Doesnt exists");

    //password chk
    const valid = await compare(password, user.password);

    if (valid) {
      const accesstok = createAccessToken(user.id);
      const refreshtok = createRefreshToken(user.id);

      user.Rtoken = refreshtok;
      await user.save();

      sendRefreshToken(res, refreshtok);
      sendAccessToken(res, req, accesstok, refreshtok);
    } else {
      return res.status(200).send({ error: "Invalid credentials" });
    }
  } catch (err) {
    res.status(401).send({
      error: `${err.message}`,
    });
  }
});

server.post("/signup", async (req, res) => {
  const { email, password, firstname, lastname } = req.body;
  console.log(email, password, firstname, lastname);
  try {
    try {
      let user = await userD.findOne({ email: email });

      if (user) {
        return res.status(200).send({ error: "User Already Exists" });
      } 
      const hashedPassword = await hash(password, 10);
        user = new userD({
            first_name: firstname,
            last_name: lastname,
            email: email,
            password: hashedPassword,
        });
        await user.save();
        res.send({ message: "Registration Successful" });
      
    } catch (err) {
      req.statusCode = 401;
      res.status(401).send({
        error: `${err.message}`,
      });
    }
  } catch (err) {
    res.status(401).send({
      error: `${err.message}`,
    });
  }
});

server.post("/protected", async (req, res) => {});

server.post("/refreshtoken", async (req, res) => {
  const token = req.body.refreshtc;
  // If we don't have a token in our request
  if (!token) return res.send({ accesstoken: "1" });

  // We have a token, let's verify it!
  let payload = null;

  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    return res.send({ accesstoken: err });
  }
  // token is valid, check if user exist
  let id = payload.userId;
  let user = await userD.findById(id);

  if (!user) return res.send({ accesstoken: "3" });
  // user exist, check if refreshtoken exist on user
  if (user.Rtoken !== token)
    return res.send({ error: "Invalid refresh token" });
  // token exist, create new Refresh- and accesstoken

  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  // update refreshtoken on user in db
  // Could have different versions instead!
  user.Rtoken = refreshtoken;
  user.save();
  // All good to go, send new refreshtoken and accesstoken
  sendRefreshToken(res, refreshtoken);
  return res.send({ accesstoken, refreshtoken });
});


//IsAdmin
server.post("/is-admin", async (req, res) => {
  try {
    const userId = isAuth(req);
    if (userId !== null) {
      let user = await userD.findById(userId);
      if (user.role === "admin") {
        return res.status(200).send(true);
      } else {
        return res.status(200).send(false);
      }
    }
  } catch (err) {
    req.statusCode = 401;
    res.status(401).send({
      error: `${err.message}`,
    });
  }
});

//

// server.listen(process.env.PORT, function () {
//   console.log("server Active Now");
// });
server.listen(PORT, function () {
  console.log(`server started on port ${PORT}`);
});
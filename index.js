import express from "express";
import rateLimit from 'express-rate-limit';
import bodyParser from "body-parser";
import { connect } from "mongoose";
import { OAuth2Client } from 'google-auth-library';
import axios from 'axios';
import dotenv from "dotenv";
import cors from 'cors';
dotenv.config();
import User from "./formats/usr.js"; // Import the User model
import { ConvertToHash, Login_Token_Generator, VerifyPassword, check_cred, generateOTP, sendOTPByEmail } from "./zlib.js";
const MONGODB_HOST = process.env.DB_HOST;
const MONGODB_PORT = process.env.DB_PORT;
const DATABASE_NAME = process.env.DB_NAME;
const MONGODB_USERNAME = process.env.MONGODB_USERNAME;
const MONGODB_PASSWORD = encodeURIComponent(process.env.MONGODB_PASSWORD);
const MONGODB_URI = `mongodb://${MONGODB_USERNAME}:${MONGODB_PASSWORD}@${MONGODB_HOST}:${MONGODB_PORT}/${DATABASE_NAME}`;





// Connection URL and database name
const url = MONGODB_HOST + ":" + MONGODB_PORT + '/' + DATABASE_NAME;







const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Max requests per minute
  message: 'Rate limit exceeded. Please try again later.',
});

//Object Format {email,token,expiryTime}
let User_list = [];


//Object Format {email,code,token,expiryTime}
let specialRq = [];



connect(url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connected to DB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });




//Register New User
async function RNU(email, password) {
  const verified = check_cred(email, password);

  if (verified.status) {
    try {
      const newUser = new User({
        email: email.toLowerCase(),
        password: await ConvertToHash(password),
        accountStatus: false,
      });
      await newUser.save();
      const expiryTime = Date.now() + 30 * 60 * 1000; // 30 minutes from now
      const token = Login_Token_Generator(email, password, expiryTime.toString());
      const SR = { code: generateOTP(), token: token, email: email, expiryTime: expiryTime };
      specialRq.push(SR);
      const link = 'https://wpico.com/activaterequest/' + SR.code.toString();
      const confirmation = await sendOTPByEmail(email, link);
      if (confirmation.success) {
        return { message: { message: "Activation link sended" }, status: true };
      } else {
        return { message: { message: "Failed to activate" }, status: false };
      }
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error (username is not unique)
        console.error("Email already registered:", error.message);
        verified.message = 'Email already registered';
        verified.status = false;
        return verified;
      } else {
        console.error("Error saving user:", error);
        verified.message = 'Error saving user';
        verified.status = false;
        return verified;
      }
    }
  } else {
    console.error("Error saving user:", error);
    verified.message = 'Error saving user';
    verified.status = false;
    return verified;
  }
}


async function Login(email, password) {
  try {
    if (User_list.length > 0) {
      const filteredUsers = User_list.filter(user => user.email === email.toLowerCase());
      if (filteredUsers.length > 0) {
        return { message: "Already Signed In", res: false };
      }
    }

    const users = await User.find({ email: email });

    if (users.length > 0) {
      const res = await VerifyPassword(password, users[0].password);

      if (res) {
        console.log("Sign-in successful", users[0].password, res);
        const expiryTime = Date.now() + 30 * 60 * 1000; // 30 minutes from now
        const token = Login_Token_Generator(email, password, expiryTime.toString());

        if (users[0].accountStatus === false) {
          //Prepare Special request
          const SR = { code: generateOTP(), token: token, email: email, expiryTime: expiryTime };
          specialRq.push(SR);
          const link = 'https://wpico.com/activaterequest/' + SR.code.toString();
          const confirmation = await sendOTPByEmail(email, link);
          if (confirmation.success) {
            return { message: { message: "Activation link sended" }, res: res };
          } else {
            return { message: { message: "Failed to activate" }, res: res };
          }
        } else {
          console.log(email, users)
          User_list.push({ email: email.toLowerCase(), token: token, expiryTime: expiryTime });
          return { message: { token: token, message: "Sign-in successful" }, res: res };
        }
        
      } else {
        console.error("Password incorrect");
        return { message: { message: "Password incorrect" }, res: false };
      }
    } else {
      console.error("Email not Registered");
      return { message: { message: "User not found" }, res: false };
    }
  } catch (error) {
    console.error("Error finding user:", error);
    return { message: { message: "Error finding user" }, res: false };
  }
}


function authEngine() {
  if (User_list != undefined) {
    User_list = User_list.filter(user => user.expiryTime > Date.now());

    User_list.forEach(user => {
      console.log(user.email + ' Status Online');
    });
  }
  setTimeout(authEngine, 1500);
}

authEngine();









const app = express();
const port = 17001;

app.use(bodyParser.json());
app.use(limiter);
app.use(cors());

app.get('/', async (req, res) => {
  res.status(200).json({ message: 'WPICO API' });
});




// Signup route
app.post('/wcipo/api/signup', async (req, res) => {
  const { email, password } = req.body;

  const r = await RNU(email, password);
  if (r.status) {
    return res.status(400).json({ message: r.message });
  } else {
    res.status(200).json({success: true, message: r.message });
  }
});


app.post('/wcipo/api/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const status = await Login(email, password);

    if (!status.res) {
      return res.status(400).json({ message: status.message });
    }
    res.status(200).json(status.message);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// SpecialRequest route
app.post('/wcipo/api/sr', async (req, res) => {
  const { code } = req.body;
  const currentTime = Date.now();
  const _user = specialRq.filter(user => user.code === code && user.expiryTime > currentTime)

  if (_user.length > 0) {
    //remove the request from list
    specialRq = specialRq.filter(user => user.code != code);
    User_list.push({ email: _user[0].email.toLowerCase(), token: _user[0].token, expiryTime: _user[0].expiryTime });
    try {
      const updatedUser = await User.findOneAndUpdate(
        { email: _user[0].email.toLowerCase() },
        { $set: { accountStatus: true } },
        { new: true }
      ).exec();

      if (updatedUser) {
        console.log('User updated:', updatedUser);
        return res.status(200).json({ message: 'Email verified', loginInfo: { email: _user[0].email.toLowerCase(), token: _user[0].token, expiryTime: _user[0].expiryTime } });
      } else {
        console.log('User not found');
        return res.status(400).json({ message: 'User not found' });
      }
    } catch (error) {
      console.error('Error updating user:', error);
      return res.status(400).json({ message: 'Error updating user' });
    }
  }
  else {
    //remove the request from list
    specialRq = specialRq.filter(user => user.code != code);
    return res.status(400).json({ message: 'Invalid or Expire Code' });
  }
});





const CLIENT_ID = '733590142223-tt4sdfibpbjh168g4kbkgkdtprf8dsu2.apps.googleusercontent.com'; // Get this from Google Cloud Console
const CLIENT_SECRET = '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'; // Keep this secret
const REDIRECT_URI = 'http://localhost:3000'; // This should match the one you set in Google Cloud Console

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const oAuth2Client = new OAuth2Client(CLIENT_ID);

app.post('/wcipo/api/gsi/authenticate', async (req, res) => {
  const code = req.body.code;

  try {
    // Exchange the authorization code for tokens
    const tokenResponse = await axios.post(GOOGLE_TOKEN_URL, {
      code: code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    });

    const idToken = tokenResponse.data.id_token;

    // Verify the ID token
    const ticket = await oAuth2Client.verifyIdToken({
      idToken: idToken,
      audience: CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
    });

    const payload = ticket.getPayload();
    const userId = payload['sub']; // This is the Google user ID
    const email = payload['email'];
    
    //check user in database
    const users = await User.find({ email: email });
    if (users.length > 0) {
      console.log('Login Now');
      if (User_list.length > 0) {
        const filteredUsers = User_list.filter(user => user.email === email.toLowerCase());
        if (filteredUsers.length > 0) {
          res.status(401).json({ success: false, message: "Already Signed In" });
        }
      }else{
        const expiryTime = Date.now() + 30 * 60 * 1000; // 30 minutes from now
        const token = Login_Token_Generator(users.email, users.password, expiryTime.toString());
        User_list.push({ email: email.toLowerCase(), token: token, expiryTime: expiryTime });
        res.status(200).json({ success: true, message: 'Sign-in successful', token: token });
      }
    } else {
      console.log('register Now');

      try {
        const newUser = new User({
          email: email.toLowerCase(),
          password: await ConvertToHash('googleUser'),
          accountStatus: true,
        });

        let _res = await newUser.save();
        const expiryTime = Date.now() + 30 * 60 * 1000; // 30 minutes from now
        const token = Login_Token_Generator(_res.email, _res.password, expiryTime.toString());
        User_list.push({ email: email.toLowerCase(), token: token, expiryTime: expiryTime });
        res.status(200).json({ success: true, message: 'Sign-in successful', token: token });
      } catch (error) {
        if (error.code === 11000) {
          // Duplicate key error (username is not unique)
          console.error("Email already registered:", error.message);
          verified.message = 'Email already registered';
          verified.status = false;
          res.status(401).json({ success: false, message: "Authentication failed" });
        } else {
          console.error("Error saving user:", error);
          verified.message = 'Error saving user';
          verified.status = false;
          res.status(401).json({ success: false, message: "Authentication failed" });
        }
      }
    }

  } catch (error) {
    console.error("Authentication error:", error);
    res.status(401).json({ success: false, message: "Authentication failed" });
  }
});





// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});


process.on('uncaughtException', function (err) {
  console.log(err.message);
});

process.on('TypeError', function (err) {
  console.log(err.message);
});
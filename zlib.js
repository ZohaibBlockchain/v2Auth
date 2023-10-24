import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';



export async function ConvertToHash(plainTxt) {
    const hashedPassword = await bcrypt.hash(plainTxt, 10); // 10 is the number of salt rounds
    return hashedPassword;
}
export async function VerifyPassword(PlainTxt, hash) {
    const result = await bcrypt.compare(PlainTxt, hash);
    console.log(result)
    return result
}

export function check_cred(email, password) {
    // Check if email and password are not empty
    if (email.length === 0 || password.length === 0) {
        return { status: false, message: "Password or Username cannot be empty" } // Return false if either is empty
    }

    if (!isValidEmail(email)) {
        return { status: false, message: "Not valid email" }
    }


    // Check if password contains only allowed characters
    if (!/^[a-zA-Z0-9!@#$%^&*()-_+=]+$/.test(password)) {
        return { status: false, message: "Password contains non acceptable special characters" }
    }

    // Check if email is at least 6 characters long
    if (email.length < 6) {
        return { status: false, message: "email too short" }
    }

    // Check if password is at least 8 characters long
    if (password.length < 8) {
        return { status: false, message: "Password too short" }
    }

    return { status: true, message: "Email Registered" } // If all checks pass, return true to indicate valid credentials
}



export function Login_Token_Generator(str1, str2, str3) {
    // Combine the two input strings
    const combinedString = str1 + str2 + str3;

    // Initialize a hash variable
    let hash = 0;

    // Loop through each character in the combined string
    for (let i = 0; i < combinedString.length; i++) {
        // Update the hash using a simple mathematical operation
        hash = (hash << 5) - hash + combinedString.charCodeAt(i);
    }

    // Ensure the hash is a positive number
    hash = Math.abs(hash);

    // Limit the hash to 10 digits
    const tenDigitHash = hash % 10000000000;

    // Convert to a string and pad with leading zeros if necessary
    const hashString = tenDigitHash.toString().padStart(10, '0');

    return hashString;
}




function isValidEmail(email) {
    // Regular expression pattern for a valid email address
    const emailPattern = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
    // Use the test() method to check if the email matches the pattern
    return emailPattern.test(email);
}




// Email configuration (use your own SMTP server or email service)
const emailConfig = {
    host: 'daweb01.iracknet.com', // SMTP server hostname
    port: 587, // SMTP server port (587 for TLS)
    secure: false, // true for 465, false for other ports
    auth: {
        user: 'support@wcipo.com', // Your email address
        pass: '_HVo,F#W*X1UU*R', // Your email password or app-specific password
    },
};





const transporter = nodemailer.createTransport(emailConfig);

// Generate a random 12-digit OTP
export function generateOTP() {
    return Math.floor(100000000000 + Math.random() * 900000000000);
}

// Function to send OTP via email
export async function sendOTPByEmail(email, link) {
    // Email configuration
    const mailOptions = {
      from: 'support@wcipo.com', // Sender's email address
      to: email,
      subject: 'OTP Verification',
      text: `Your WPICO Account Activation link is: ${link}`,
    };
  
    try {
      // Send OTP via email
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent: ' + info.response);
      return { success: true, message: 'OTP sent successfully' };
    } catch (error) {
      console.error(error);
      return { success: false, message: 'Error sending OTP' };
    }
  }
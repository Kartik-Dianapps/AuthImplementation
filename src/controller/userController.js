import "dotenv/config"
import jwt from "jsonwebtoken";
import verifyEmail from "../emailVerify/verifyEmail.js";
import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import Session from "../models/sessionModel.js";
import sendOtpMail from "../emailVerify/sendOtpMail.js";

const registerUser = async (req, res) => {
    try {
        let { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required..." })
        }

        const existingUser = await User.findOne({ email: email });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists with this email..." })
        }

        const hash = await bcrypt.hash(password, 10);
        password = hash;

        const newUser = await User.create({ username: username, email: email, password: password })

        // create a jwt then save it to db and sends a verification mail to user
        const token = jwt.sign({ id: newUser._id }, process.env.SECRET_KEY, { expiresIn: "10m" })

        newUser.token = token

        await newUser.save();

        await verifyEmail(token, email)
        console.log("Email Sent...");

        return res.status(201).json({ data: newUser, message: "User Registered Successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: "Registration Failed" })
    }
}

const verification = async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Please provide token..." })
        }

        const token = authHeader.substring(authHeader.indexOf(" ") + 1);

        let decoded;

        try {
            decoded = jwt.verify(token, process.env.SECRET_KEY);
        } catch (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(400).json({ message: "Registration Token has Expired..." })
            }

            return res.status(400).json({ message: "Token Verification Failed..." })
        }

        const user = await User.findById(decoded.id);
        user.token = null
        user.isVerified = true

        await user.save();
        return res.status(200).json({ message: "Email Verified Successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const login = async (req, res) => {
    try {
        let { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Please provide email and password..." })
        }

        const user = await User.findOne({ email: email })

        if (!user) {
            return res.status(400).json({ message: "Please Enter correct email..." })
        }

        const passwordCheck = await bcrypt.compare(password, user.password);

        if (!passwordCheck) {
            return res.status(400).json({ message: "Please Enter correct password..." })
        }

        // check its email is verified or not

        if (!user.isVerified) {
            return res.status(403).json({ message: "First verify your email then try to login..." })
        }

        // Check for existing session then delete old one then create again
        let existingSession = await Session.findOne({ userId: user._id })
        if (existingSession) {
            await Session.deleteOne({ userId: user._id })
        }

        await Session.create({ userId: user._id })

        // Generate Tokens
        // access token is short lived and refresh token is long lived
        // so the use of refresh token is that access token expires before so to generate again the access token we use refresh token
        const accessToken = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: "10d" })
        const refreshToken = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: "30d" })

        user.isLoggedIn = true;

        await user.save();

        return res.status(200).json({ message: `Welcome Back ${user.username}...`, accessToken: accessToken, refreshToken: refreshToken, user: user })
    }
    catch (error) {
        console.log(error);

        return res.status(500).json({ message: error.message })
    }
}

const logout = async (req, res) => {
    try {
        const userId = req.userId;

        await Session.deleteOne({ userId: userId });

        await User.findByIdAndUpdate({ _id: userId }, { isLoggedIn: false });

        return res.status(200).json({ message: "Logout Successfully..." })
    }
    catch (error) {
        res.status(500).json({ message: "Logout Failed..." })
    }
}

const forgotPassword = async (req, res) => {
    try {
        // to reset password what we need first

        // Step 1 - get email of user
        const { email } = req.body;

        // Step 2 - Now check that user exists or not with this email
        const user = await User.findOne({ email: email });

        // if user with this email not exists
        if (!user) {
            return res.status(400).json({ message: "User not found with this email, Please Enter correct one..." })
        }

        // Step 3 - if user with this email exists then send otp
        // Generate OTP and its expiry
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(Date.now() + 10 * 60 * 1000)

        // Step 4 - save the otp and its expiry
        user.otp = otp;
        user.otpExpiry = expiry;

        await user.save();

        await sendOtpMail(email, otp);

        return res.status(200).json({ message: "OTP sent for resetting the password..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const verifyOtp = async (req, res) => {
    try {
        const { otp } = req.body
        const email = req.params.email;

        if (!otp) {
            return res.status(400).json({ message: "OTP is required..." })
        }

        const user = await User.findOne({ email: email })

        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        if (!user.otp) {
            return res.status(400).json({ message: "OTP already verified or OTP not generated..." })
        }

        if (user.otpExpiry < new Date()) {
            return res.status(400).json({ message: "OTP has expired.Please generate new one..." })
        }

        if (user.otp !== otp) {
            return res.status(400).json({ message: "Please Enter a valid OTP..." })
        }

        user.otp = null;
        user.otpExpiry = null;

        await user.save();

        return res.status(200).json({ message: "OTP verified successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const changePassword = async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const email = req.params.email;

        if (!newPassword || !confirmPassword) {
            return res.status(400).json("All fields are required...")
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "newPassword and confirmPassword does not match..." })
        }

        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        const hashPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashPassword

        await user.save();
        return res.status(200).json({ message: "Password changed successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

export { registerUser, verification, login, logout, forgotPassword, verifyOtp, changePassword }
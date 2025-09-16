import "dotenv/config"
import jwt from "jsonwebtoken";
import verifyEmail from "../emailVerify/verifyEmail.js";
import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import Session from "../models/sessionModel.js";
import sendOtpMail from "../emailVerify/sendOtpMail.js";
import { userValidationSchema, loginValidationSchema, passwordCheckValidationSchema } from "../Validation/userValidate.js";
import OTP from "../models/OtpModel.js";
import { ObjectId } from "mongodb"

const registerUser = async (req, res) => {
    try {

        const { error, value } = userValidationSchema.validate(req.body);

        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        let { username, email, password } = value;

        const existingUser = await User.findOne({ email: email });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists with this email..." })
        }

        const hash = await bcrypt.hash(password, 10);
        password = hash;

        const newUser = await User.create({ username: username, email: email, password: password })

        await newUser.save();

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(Date.now() + 5 * 60 * 1000)

        const existingOtp = await OTP.findOne({ userId: newUser._id })
        console.log(existingOtp);

        if (existingOtp) {
            await OTP.deleteMany({ userId: newUser._id })
        }

        await OTP.create({ userId: newUser._id, otp: otp, otpExpiry: expiry })

        await verifyEmail(email, otp);
        console.log("OTP Sent...");

        return res.status(201).json({ data: newUser, message: "User Registered Successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: "Registration Failed" })
    }
}

const verifyEmailOtp = async (req, res) => {
    try {
        const { otp, email } = req.body

        if (!otp) {
            return res.status(400).json({ message: "OTP is required..." })
        }

        const user = await User.findOne({ email: email })

        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        const oneTimePin = await OTP.findOne({ userId: user._id })

        if (!oneTimePin) {
            return res.status(400).json({ message: "OTP not generated..." })
        }
        if (oneTimePin.isVerified) {
            return res.status(400).json({ message: "OTP already verified..." })
        }

        if (oneTimePin.otpExpiry < new Date()) {
            return res.status(400).json({ message: "OTP has expired.Please generate new one..." })
        }

        if (oneTimePin.otp !== otp) {
            return res.status(400).json({ message: "Please Enter correct OTP..." })
        }

        oneTimePin.isVerified = true;
        await oneTimePin.save();

        user.isVerified = true;
        await user.save();

        return res.status(200).json({ message: "OTP for Email Verification verified successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const login = async (req, res) => {
    try {

        let { error, value } = loginValidationSchema.validate(req.body)

        if (error) {
            return res.status(400).json({ message: error.details[0].message })
        }

        let { email, password } = value;
        // Remove duplicate validations from business logic

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

        const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: "3d" })

        await Session.create({ userId: user._id, token: token, tokenExpiry: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000) })

        return res.status(200).json({ message: `Welcome Back ${user.username}...`, email: user.email, token: token })
    }
    catch (error) {
        console.log(error);

        return res.status(500).json({ message: error.message })
    }
}

// Logout functionality has failed : 
const logout = async (req, res) => {
    try {
        let token = req.headers.authorization;
        token = token.substring(token.indexOf(" ") + 1);
        const userId = req.userId;

        await Session.deleteOne({ userId: userId, token: token });

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
        const expiry = new Date(Date.now() + 5 * 60 * 1000)

        // Step 4 - save the otp and its expiry
        const time = new Date();
        const existingOtp = await OTP.findOne({ userId: user._id })
        console.log(existingOtp);

        if (existingOtp) {
            await OTP.deleteMany({ userId: user._id })
        }

        await OTP.create({ userId: user._id, otp: otp, otpExpiry: expiry })

        await sendOtpMail(email, otp);

        return res.status(200).json({ message: "OTP sent for resetting the password..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const verifyOtp = async (req, res) => {
    try {
        const { otp, email } = req.body

        if (!otp) {
            return res.status(400).json({ message: "OTP is required..." })
        }

        const user = await User.findOne({ email: email })

        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        const oneTimePin = await OTP.findOne({ userId: user._id })

        if (!oneTimePin) {
            return res.status(400).json({ message: "OTP not generated..." })
        }
        if (oneTimePin.isVerified) {
            return res.status(400).json({ message: "OTP already verified..." })
        }

        if (oneTimePin.otpExpiry < new Date()) {
            return res.status(400).json({ message: "OTP has expired.Please generate new one..." })
        }

        if (oneTimePin.otp !== otp) {
            return res.status(400).json({ message: "Please Enter correct OTP..." })
        }

        oneTimePin.isVerified = true;
        await oneTimePin.save();

        const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: "5m" })

        user.token = token;
        await user.save();

        return res.status(200).json({ token: token, message: "OTP verified successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

// OTP verification and changePassword Functionalities are not correct!
const changePassword = async (req, res) => {
    try {

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Please provide token or provided invalid token..." })
        }

        const token = authHeader.substring(authHeader.indexOf(" ") + 1);

        let decoded;

        try {
            decoded = jwt.verify(token, process.env.SECRET_KEY);

            const user = await User.findById(decoded.id);

            if (user.token !== token) {
                return res.status(400).json({ message: "Please provide same token..." })
            }

        } catch (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(400).json({ message: "changePassword API Token has Expired..." })
            }

            return res.status(400).json({ message: "Token Verification Failed..." })
        }

        let { error, value } = passwordCheckValidationSchema.validate(req.body);

        if (error) {
            console.log(error);
            return res.status(400).json({ message: error.details[0].message })
        }

        const { newPassword, email } = value;

        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        const hashPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashPassword
        user.token = null;

        await user.save();
        return res.status(200).json({ message: "Password changed successfully..." })
    }
    catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const profile = async (req, res) => {
    try {
        const id = req.userId;

        const user = await User.findById(id);

        return res.status(200).json({ userData: { username: user.username, email: user.email } })
    }
    catch (error) {
        return res.status(500).json({ message: "Error while fetching the profile..." })
    }
}

export { registerUser, login, logout, forgotPassword, verifyOtp, verifyEmailOtp, changePassword, profile }
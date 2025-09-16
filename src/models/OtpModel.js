import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },
    otp: {
        type: String,
        default: null
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    otpExpiry: {
        type: Date,
        default: null
    }
}, { timestamps: true })

const OTP = mongoose.model("OTP", otpSchema);

export default OTP
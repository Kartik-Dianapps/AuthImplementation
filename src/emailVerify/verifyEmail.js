import nodemailer from "nodemailer";
import "dotenv/config";

const verifyEmail = async (email, otp) => {

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PSWD
        }
    })

    const mailConfigurations = {
        from: process.env.MAIL_USER,
        to: email,
        subject: "OTP for Email Verification...",
        html: `<p>Your OTP for Email Verification is: <b>${otp}</b>. It is valid for 5 minutes.</p>`
    }

    const info = await transporter.sendMail(mailConfigurations);
    console.log("Email sent successfully");
    console.log(info);
}

export default verifyEmail;
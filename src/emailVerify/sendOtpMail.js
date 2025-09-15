import nodemailer from "nodemailer";
import "dotenv/config";

const sendOtpMail = async (email, otp) => {

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
        subject: "OTP for password reset...",
        html: `<p>Your OTP for password reset is: <b>${otp}</b>. It is valid for 10 minutes.</p>`
    }

    const info = await transporter.sendMail(mailConfigurations);
    console.log("Email sent successfully");
    console.log(info);
}

export default sendOtpMail
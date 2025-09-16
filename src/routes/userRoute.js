import express from "express";
import { changePassword, forgotPassword, login, logout, profile, registerUser, verifyEmailOtp, verifyOtp } from "../controller/userController.js";
import verifyToken from "../middleware/auth.js";
const router = express.Router();

router.post("/register", registerUser)
router.post("/verifyEmail", verifyEmailOtp)
router.post("/login", login)
router.post("/logout", verifyToken, logout)
router.post("/forgotPassword", forgotPassword)
router.post("/verifyOtp", verifyOtp)
router.post("/changePassword", changePassword)
router.get("/profile", verifyToken, profile)

export default router
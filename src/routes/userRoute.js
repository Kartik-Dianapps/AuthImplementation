import express from "express";
import { changePassword, forgotPassword, login, logout, registerUser, verification, verifyOtp } from "../controller/userController.js";
import verifyToken from "../middleware/auth.js";
const router = express.Router();

router.post("/register", registerUser)
router.post("/verify", verification)
router.post("/login", login)
router.post("/logout", verifyToken, logout)
router.post("/forgotPassword", forgotPassword)
router.post("/verifyOtp/:email", verifyOtp)
router.post("/changePassword/:email", changePassword)

export default router
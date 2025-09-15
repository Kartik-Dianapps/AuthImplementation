import jwt from "jsonwebtoken"
import User from "../models/userModel.js";

const verifyToken = async (req, res, next) => {
    try {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer ")) {
            res.status(401);
            return res.json({ message: "Access Token is missing or provided invalid token..." })
        }

        token = token.substring(token.indexOf(" ") + 1);

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.SECRET_KEY);
            console.log(decoded);
        }
        catch (error) {
            if (error.name === "TokenExpiredError") {
                return res.status(400).json({ message: "Access Token has Expired, Use refresh token to generate again..." })
            }
            return res.status(400).json({ message: "Provided Invalid Access Token..." })
        }

        const { id } = decoded;

        const user = await User.findById(id);
        if (!user) {
            return res.status(400).json({ message: "User not found..." })
        }

        req.userId = user._id;
        next();
    }
    catch (error) {
        res.status(500).json({ message: error.message })
    }
}

export default verifyToken;
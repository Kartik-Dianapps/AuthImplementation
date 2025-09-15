import "dotenv/config";
import express from "express";
import connectDB from "./src/database/connection.js";
import userRouter from "./src/routes/userRoute.js"

const app = express();

const port = process.env.PORT;

connectDB();

app.use(express.json())
app.use("/user", userRouter);

app.listen(port,() => {
    console.log(`Server is running on port ${port}`);
})
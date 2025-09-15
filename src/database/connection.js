import mongoose from "mongoose"

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.CONNECTION_STRING);
        console.log("Connection Successful...");

    } catch (error) {
        console.log("Mongodb connection error:", error.message);
    }
}

export default connectDB;
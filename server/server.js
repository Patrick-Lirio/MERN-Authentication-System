import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoute.js";
import userRouter from "./routes/userRoute.js";

const app = express();

const PORT = process.env.PORT || 5002;

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

// API Endpoints
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});

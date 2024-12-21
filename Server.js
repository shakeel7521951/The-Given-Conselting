import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import connectDB from "./connectionDB/ConnDB.js";
import userRoute from "./routes/userRoute.js";
import { v2  } from "cloudinary";
import fileUpload from "express-fileupload";
import cors from 'cors';
import error from './middlewhare/error.js'

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cookieParser()); 

app.use(
  cors({
    origin: process.env.FRONT_END_URL,
    credentials: true, 
  })
);

app.use(express.json({ limit: "50mb" }));
app.use(fileUpload({ useTempFiles: true, tempFileDir: "/tmp/" }));

app.get("/", (req, res) => {
  res.send("The given consulting website...");
});

v2.config({
  cloud_name: process.env.Cloud_Name,
  api_key: process.env.Cloud_API_Key,
  api_secret: process.env.API_Secret_Key,
});

app.use("/api/v1", userRoute);

app.use(error)

app.listen(port, async () => {
  console.log(`The server is running on port ${port}.`);
  connectDB();
});

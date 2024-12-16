import { catchAsyncError } from "../middlewhare/catchAsyncError.js";
import User from "../models/userModel.js";
import errorHandler from "./errorHandler.js";
import jwt from "jsonwebtoken";

export const isUserLogedIn = catchAsyncError(async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return next(new errorHandler("Please login to access this page", 401));
  }

  try {
    const decodeData = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decodeData.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No user found!",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return next(new errorHandler("Invalid or expired token", 401));
  }
});

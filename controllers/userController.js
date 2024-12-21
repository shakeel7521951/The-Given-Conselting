import { catchAsyncError } from "../middlewhare/catchAsyncError.js";
import User from "../models/userModel.js";
import { v2 as cloudinary } from "cloudinary";
import errorHandler from "../utils/errorHandler.js";
import bcrypt from "bcrypt";
import { sendMail } from "../sendGrid.js";

export const signup = catchAsyncError(async (req, res, next) => {
  const { name, email, password, confirmPassword } = req.body;

  // Validate that all fields are provided
  if (!name || !email || !password || !confirmPassword) {
    return next(new errorHandler("All fields are required", 400));
  }

  if (password !== confirmPassword) {
    return next(new errorHandler("Passwords do not match", 422));
  }
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new errorHandler("User already exists", 400));
  }

  const newUser = new User({
    name,
    email,
    password,
  });

  const OTP = newUser.generateOTP();
  await newUser.save(); 

  const subject = "Welcome to The Given Consulting!";
  const text = `
    <p>Hello <strong>${name}</strong>,</p>
    <p>Thank you for joining us at The Given Consulting! We're excited to have you on board.</p>
    <p>To complete your registration, please use the OTP below for verification:</p>
    <h3 style="font-size: 32px; font-weight: bold; color: #4CAF50;">${OTP}</h3>
    <p>If you need assistance, feel free to reach out to us.</p>
    <p>Best regards,</p>
    <p>The Given Consulting Team</p>
  `;

  // Send the OTP via email
  await sendMail(email, subject, text);

  res.status(201).json({
    success: true,
    message: `Email verification OTP sent to: ${email}`,
    newUser,
  });
});

export const verifyUser = catchAsyncError(async (req, res, next) => {
  const { email, otp } = req.body;

  if (!otp) {
    return next(new errorHandler("Please enter your OTP", 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new errorHandler("User with this email not found", 404));
  }

  if (user.otp !== otp || Date.now() > user.otpExpires) {
    return next(new errorHandler("Invalid or Expired OTP", 400));
  }

  const token = user.getJwtToken();
  user.otp = undefined;
  user.otpExpires = undefined;
  user.status = "verified";
  await user.save();

  res
    .status(200)
    .cookie("token", token, {
      expires: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
      httpOnly: true,
    })
    .json({
      success: true,
      message: "Welcome to The Given Consulting Website",
    });
});

export const login = catchAsyncError(async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return next(new errorHandler("User with this email not found!", 404));
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return next(new errorHandler("Wrong password", 400));
  }

  const token = user.getJwtToken();

  if (user.status === "unverified") {
    await User.findOneAndDelete({ email });
  }

  res
    .status(200)
    .cookie("token", token, {
      expires: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
      httpOnly: true,
    })
    .json({
      success: true,
      message: "Login successful",
      user,
    });
});

export const logout = catchAsyncError(async (req, res, next) => {
  const userId = req.user?._id;
  if (!userId) {
    return res.status(400).json({
      success: false,
      message: "User not found",
    });
  }
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(200).json({
    success: true,
    message: "User logged out successfully",
  });
});


export const myProfile = catchAsyncError(async (req, res, next) => {
  const user = req.user;

  res.status(200).json({
    success: true,
    user,
  });
});

export const updateProfile = catchAsyncError(async (req, res, next) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    return next(new errorHandler("User not found!", 404));
  }

  const { name, role } = req.body;
  const file = req.files?.profilePic;

  if (file) {
    const result = await cloudinary.uploader.upload(file.tempFilePath, {
      folder: "User Profiles",
    });

    if (user.profilePic?.public_id) {
      await cloudinary.uploader.destroy(user.profilePic.public_id);
    }

    user.profilePic = {
      public_id: result.public_id,
      url: result.secure_url,
    };
  }

  if (name) user.name = name;
  if (role) user.role = role;

  await user.save();

  res.status(200).json({
    success: true,
    message: "Profile updated successfully",
    user,
  });
});

export const updatePassword = catchAsyncError(async (req, res, next) => {
  const { oldPassword, password, confirmPassword } = req.body;

  if (!oldPassword || !password || !confirmPassword) {
    return next(new errorHandler("All fields are required", 400));
  }

  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new errorHandler("User not found!", 404));
  }

  const isMatch = await user.comparePassword(oldPassword);
  if (!isMatch) {
    return next(new errorHandler("Old password is incorrect!", 401));
  }

  if (password !== confirmPassword) {
    return next(new errorHandler("Passwords do not match!", 400));
  }

  user.password = password;
  await user.save();

  res.status(200).json({
    success: true,
    message: "Password updated successfully",
  });
});

export const forgotPassword = catchAsyncError(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new errorHandler("Please provide an email address", 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new errorHandler("User not found with this email", 404));
  }

  const OTP = user.generateOTP();

  const message = `<p>Hi there,</p>
  <p>We received a request to reset your password. Your One-Time Password (OTP) for this process is:</p>
  <h2 style="font-size: 32px; font-weight: bold; color: #4CAF50;">${OTP}</h2>
  <p>If you did not make this request, please ignore this email. Rest assured, your account is safe.</p>
  <p>If you need further assistance, feel free to reach out to us!</p>
  <p>Best regards,<br>Lusail Numbers Plate Team</p>`;

  try {
    await sendMail(email, "Password Reset OTP", message);
    user.otp = OTP;
    await user.save();

    res.status(200).json({
      success: true,
      message: `OTP sent to ${email} successfully`,
    });
  } catch (error) {
    console.error("Error while processing forgot password:", error.message);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();
    return next(new errorHandler("Failed to send OTP email", 500));
  }
});

export const verifyOTP = catchAsyncError(async (req, res, next) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return next(new errorHandler("Email and otp is required", 401));
  }
  const user = await User.findOne({ email });
  if (!user) {
    return next(new errorHandler("User with this email not found!", 404));
  }
  if (user.otp !== otp || user.otpExpires < Date.now()) {
    return next(new errorHandler("Invalid or expired OTP", 400));
  }
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();
  res
    .status(200)
    .json({ success: true, message: "OTP verified successfully!" });
});

export const resetPassword = catchAsyncError(async (req, res, next) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return next(new errorHandler("Email and password is required!", 401));
  }
  const user = await User.findOne({ email });
  if (!user) {
    return next(new errorHandler("User with this email not found!", 404));
  }
  user.password = newPassword;
  await user.save();
  res
    .status(200)
    .json({ success: true, message: "Password reset successfully" });
});

export const getSingleUser = catchAsyncError(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new errorHandler("User not found!", 404));
  }
  res.status(200).json({
    success: true,
    user,
  });
});

export const getAllUsers = catchAsyncError(async (req, res, next) => {
  const users = await User.find();

  if (users.length < 1) {
    return res.status(200).json({
      success: true,
      message: "No users found",
      users: [],
    });
  }

  res.status(200).json({
    success: true,
    count: users.length,
    users,
  });
});

export const deleteMyProfile = catchAsyncError(async (req, res, next) => {
  const deleteProfile = await User.findByIdAndDelete(req.user._id);
  if (!deleteProfile) {
    return next(new errorHandler("Error in deleting User!", 401));
  }
  // await cloudinary.uploader.destroy(deleteProfile.profilePic.public_id);
  res.status(200).json({
    success: true,
    message: "Profile deleted successfully",
  });
});

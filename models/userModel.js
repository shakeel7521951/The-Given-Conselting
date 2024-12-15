import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: [validator.isEmail, "Please enter a valid email"],
  },
  profilePic: {
    public_id: { type: String, required: false },
    url: { type: String, required: false },
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
    required: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minLength: [8, "Password must be at least 8 characters"],
  },
  token: String,
  otp:String,
  otpExpires:Date,
  createdDate: {
    type: Date,
    default: Date.now,
  },
});

// Hash password before saving the document
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Method to generate JWT token
userSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

userSchema.methods.generateOTP = function(){
  const otp = Math.floor(100000 + Math.random()*900000).toString();
  this.otp = otp;
  this.otpExpires = Date.now()+5*60*1000;
  return otp;
}

const User = mongoose.model("User", userSchema);

export default User;

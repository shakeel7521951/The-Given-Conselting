import { forgotPassword, login, logout, myProfile, resetPassword, signup, updatePassword, updateProfile, verifyOTP } from '../controllers/userController.js';
import express from 'express';
import { isUserLogedIn } from '../utils/auth.js';
const router = express.Router();

router.post('/signup',signup);
router.post('/login',login);
router.post('/logout',isUserLogedIn,logout);
router.get('/my-profile',isUserLogedIn,myProfile);
router.put('/update-profile',isUserLogedIn,updateProfile);
router.put('/update-password',isUserLogedIn,updatePassword);
router.put('/forgot-password',forgotPassword);
router.put('/verify-otp',verifyOTP);
router.put('/reset-password',resetPassword);

export default router;
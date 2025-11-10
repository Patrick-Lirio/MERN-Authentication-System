import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";

export const register = async (req, res) => {
  let { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(404)
      .json({ success: false, message: "All fields are required" });
  }
  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res
        .status(404)
        .json({ success: false, message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new userModel({ name, email, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    // Sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: `Welcome to Patrick's App`,
      text: `Hi ${name}, Welcome to Patrick's App. Your account has been created with this ${email} email.`,
    };
    await transporter.sendMail(mailOptions);
    // Generate a response
    res.status(201).json({ success: true, message: "User registered" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  let { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(404)
      .json({ success: false, message: "All fields are required" });
  }

  email = email.toLowerCase().trim();

  try {
    const user = await userModel.findOne({ email });
    console.log(user);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({ success: true, message: "User logged in" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({ success: true, message: "User logged out" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

export const sendVerifyOtp = async (req, res) => {
  try {
    // const { userId } = req.body;
    // const user = await userModel.findById(userId);
    const { id } = req.user;
    const user = await userModel.findById(id);

    if (user.isAccountVerified) {
      return res
        .status(400)
        .json({ success: false, message: "Account already verified" });
    }
    // it will generate 6 random number
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    //store it to the column verifyOtp
    user.verifyOtp = otp;
    // generate an expiry time that will last for a day
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
    // save it
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: `Account Verification OTP`,
      text: `Your OTP is ${otp}.Verify your account using this OTP. This OTP will expire in 24 hours.`,
    };
    await transporter.sendMail(mailOptions);
    return res
      .status(200)
      .json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// verify the email using OTP
export const verifyEmail = async (req, res) => {
  //   const { userId, otp } = req.body;
  const { otp } = req.body;
  const { id: userId } = req.user;
  if (!userId || !otp) {
    return res.status(400).json({ success: false, message: "Missing Details" });
  }
  try {
    const user = await userModel.findById(userId);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP Expired" });
    }
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;
    await user.save();
    return res
      .status(200)
      .json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// check if user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    return res
      .status(200)
      .json({ success: true, message: "User authenticated" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// send password reset otp
export const sendResetPasswordOtp = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required" });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    // it will generate 6 random number
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    //store it to the column verifyOtp
    user.resetOtp = otp;
    // generate an expiry time that will last for a day
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
    // save it
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: `Password Reset OTP`,
      text: `Your OTP is ${otp}.Reset your Password using this OTP. This OTP will expire in 15 minutes.`,
    };
    await transporter.sendMail(mailOptions);
    return res
      .status(200)
      .json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Reset User password
export const resetPassword = async (req, res) => {
  const { otp, email, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Email, OTP and New Password are required",
    });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    if (user.resetOtpExpireAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP Expired" });
    }
    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;
    await user.save();
    return res
      .status(200)
      .json({ success: true, message: "Password reset successfully" });
  } catch {
    res.status(500).json({ success: false, message: error.message });
  }
};

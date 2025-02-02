import User from "../models/User.js";
import RefreshToken from "../models/RefreshToken.js";
import TokenBlacklist from "../models/TokenBlacklist.js";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";

// 🔐 Generate JWT Tokens
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

const generateRefreshToken = async (userId) => {
  const token = jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES,
  });

  await RefreshToken.create({
    token,
    userId,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
  });

  return token;
};

// ✅ Secure Cookie Options
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
};

// 🛡️ Register User
export const register = async (req, res) => {
  try {
    // ✅ Validate Input
    await Promise.all([
      body("email").isEmail().withMessage("Invalid email").run(req),
      body("username")
        .trim()
        .notEmpty()
        .withMessage("Username is required")
        .run(req),
      body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 6 characters")
        .run(req),
    ]);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // ✅ Extract Data
    const { email, username, password } = req.body;

    // ✅ Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Email or username already exists" });
    }

    // ✅ Create New User
    const user = new User({ email, username, password });
    await user.save();

    // ✅ Generate Tokens
    const accessToken = generateToken(user._id);
    const refreshToken = await generateRefreshToken(user._id);

    // ✅ Store active session
    user.activeSession = refreshToken;
    await user.save();

    // ✅ Set Cookies
    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000,
    }); // 15 min
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    }); // 30 days

    res.status(201).json({ message: "User registered and logged in!" });
  } catch (error) {
    console.error("❌ Registration Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// 🛠️ FIX: Regenerate CSRF Token After Login
export const login = async (req, res) => {
  await body("email").isEmail().run(req);
  await body("password").notEmpty().run(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await user.matchPassword(password))) {
      if (user.activeSession) {
        console.log(
          `🔄 User ${user.username} is already logged in. Logging them out.`
        );
        await logoutUser(user.activeSession);
      }

      const accessToken = generateToken(user._id);
      const refreshToken = await generateRefreshToken(user._id);

      user.activeSession = refreshToken;
      await user.save();

      res.cookie("accessToken", accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
      });
      res.cookie("refreshToken", refreshToken, {
        ...cookieOptions,
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });

      // 🔥 FIX: Regenerate CSRF Token
      res.json({ message: "Login successful!", csrfToken: req.csrfToken() });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// 🛠️ FIX: Regenerate CSRF Token After Logout
export const logout = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (refreshToken) {
    await logoutUser(refreshToken);
  }

  res.clearCookie("accessToken", { ...cookieOptions, path: "/" });
  res.clearCookie("refreshToken", { ...cookieOptions, path: "/" });

  // 🔥 FIX: Regenerate CSRF Token
  res.json({ message: "Logged out successfully!", csrfToken: req.csrfToken() });
};

// ♻️ Helper Function to Logout User (Ensures Full Session Reset)
const logoutUser = async (refreshToken) => {
  if (!refreshToken) return;

  const user = await User.findOne({ activeSession: refreshToken });
  if (user) {
    user.activeSession = null; // ✅ Clear active session
    await user.save();
  }

  // ✅ Instead of manual cleanup, set `expiresAt` for automatic removal
  await TokenBlacklist.create({
    token: refreshToken,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
  });

  console.log("✅ User session fully cleared.");
};

// ♻️ Refresh Token (Ensures Token is Valid and Not Blacklisted)
export const refreshToken = async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) return res.status(401).json({ message: "Unauthorized" });

  try {
    // ✅ Check if token is blacklisted
    const blacklisted = await TokenBlacklist.findOne({ token: refreshToken });
    if (blacklisted)
      return res.status(403).json({ message: "Invalid refresh token" });

    // ✅ Check if refresh token exists in DB
    const storedToken = await RefreshToken.findOne({ token: refreshToken });
    if (!storedToken)
      return res.status(403).json({ message: "Invalid refresh token" });

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user)
      return res.status(403).json({ message: "Invalid refresh token" });

    // ✅ Blacklist used refresh token
    await TokenBlacklist.create({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    // 🔥 Delete the old refresh token & issue a new one
    await RefreshToken.deleteOne({ token: refreshToken });

    const newAccessToken = generateToken(user._id);
    const newRefreshToken = await generateRefreshToken(user._id);

    res.cookie("accessToken", newAccessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000,
    });
    res.cookie("refreshToken", newRefreshToken, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
};

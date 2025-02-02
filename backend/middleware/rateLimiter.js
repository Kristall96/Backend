import rateLimit from "express-rate-limit";

// 🔐 Limit login attempts (max 5 attempts per 15 minutes)
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Max 5 attempts per window
  message: "Too many login attempts. Please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

// 🔐 Limit registration attempts (max 10 per hour)
export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: "Too many registration attempts. Please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

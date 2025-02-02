import express from "express";
import jwt from "jsonwebtoken"; // ✅ Fix: Import jwt
import {
  register,
  login,
  logout,
  refreshToken,
} from "../controllers/authController.js";
import { loginLimiter, registerLimiter } from "../middleware/rateLimiter.js";
import { protect } from "../middleware/authMiddleware.js"; // ✅ Protect routes with authentication
import { authorizeRoles } from "../middleware/roleMiddleware.js"; // ✅ Restrict access based on roles

const router = express.Router();

router.post("/register", registerLimiter, register);
router.post("/login", loginLimiter, login);
router.post("/logout", logout);
router.post("/refresh", refreshToken);

// ✅ Route to Verify Token (Remains Unchanged)
router.get("/verify-token", (req, res) => {
  try {
    const token = req.cookies.accessToken;

    if (!token) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Invalid token" });
      }
      res.status(200).json({ message: "Authenticated", userId: decoded.id });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Protected Admin Route (Only Accessible by Admins)
router.get("/admin", protect, authorizeRoles("admin"), (req, res) => {
  res.status(200).json({ message: "Welcome, Admin!" });
});

// ✅ Protected Moderator Route (Accessible by Admins & Moderators)
router.get(
  "/moderator",
  protect,
  authorizeRoles("admin", "moderator"),
  (req, res) => {
    res.status(200).json({ message: "Welcome, Moderator or Admin!" });
  }
);

export default router;

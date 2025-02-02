import jwt from "jsonwebtoken";
import User from "../models/User.js";
import TokenBlacklist from "../models/TokenBlacklist.js";

export const protect = async (req, res, next) => {
  let token = req.headers.authorization;

  if (token && token.startsWith("Bearer ")) {
    try {
      token = token.split(" ")[1];

      // Check if token is blacklisted
      const blacklisted = await TokenBlacklist.findOne({ token });
      if (blacklisted) {
        return res.status(401).json({ message: "Token has been revoked" });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select("-password");
      next();
    } catch (error) {
      return res.status(401).json({ message: "Unauthorized" });
    }
  } else {
    res.status(401).json({ message: "No token provided" });
  }
};

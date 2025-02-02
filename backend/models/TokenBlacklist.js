import mongoose from "mongoose";

const TokenBlacklistSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true, index: { expires: "30d" } }, // ✅ Auto-delete after 30 days
});

const TokenBlacklist = mongoose.model("TokenBlacklist", TokenBlacklistSchema);
export default TokenBlacklist;

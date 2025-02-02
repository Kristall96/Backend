import mongoose from "mongoose";

const RefreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  expiresAt: { type: Date, required: true, index: { expires: "30d" } }, // ✅ Auto-delete after 30 days
});

const RefreshToken = mongoose.model("RefreshToken", RefreshTokenSchema);
export default RefreshToken;

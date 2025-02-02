import mongoose from "mongoose";
import bcrypt from "bcrypt";

// 🎭 Define User Roles
const rolesEnum = ["admin", "moderator", "superUser", "user"];

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    // Optional Fields
    name: { type: String },
    surname: { type: String },
    phone: { type: String, unique: true, sparse: true },
    address: { type: String },
    postcode: { type: String },
    points: { type: Number, default: 0 },
    role: { type: String, enum: rolesEnum, default: "user" },
    refreshTokens: [{ type: String }], // ✅ Store multiple refresh tokens
    activeSession: { type: String, default: null },
  },
  { timestamps: true }
);

// 🔒 Hash password before saving
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(14);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// 🔑 Compare entered password with hashed password
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model("User", UserSchema);
export default User;

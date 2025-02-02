import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import csurf from "csurf";
import crypto from "crypto";
import { fileURLToPath } from "url";
import path from "path";
import connectDB from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";

dotenv.config();
connectDB();
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Set View Engine to EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "frontend"));

// ✅ Middleware to Generate a New CSP Nonce for Each Request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  next();
});
app.use(
  helmet({
    contentSecurityPolicy: false, // Disable default CSP since you manually define one
  })
);

// ✅ Fix CORS
app.use(
  cors({
    origin: ["http://localhost:5500", "http://127.0.0.1:5500"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  })
);

// ✅ Fix Content-Security-Policy (CSP) for Third-Party Scripts
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    `
      default-src 'self';
      script-src 'self' 'nonce-${res.locals.nonce}' https://apis.google.com https://cdn.jsdelivr.net;
      style-src 'self' 'nonce-${res.locals.nonce}' https://fonts.googleapis.com;
      font-src 'self' https://fonts.gstatic.com;
      img-src 'self' data:;
      connect-src 'self' http://localhost:4000;
      frame-ancestors 'none';
      object-src 'none';
      base-uri 'self';
      form-action 'self';
    `.replace(/\s{2,}/g, " ") // ✅ Clean up spaces
  );
  next();
});

// ✅ Logging Middleware
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// ✅ Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ Secure Cookie Settings
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
};

// ✅ CSRF Protection Middleware
const csrfProtection = csurf({
  cookie: {
    key: "_csrf", // ✅ Store CSRF token in a cookie
    httpOnly: true, // ✅ Prevent JavaScript from accessing the token
    secure: process.env.NODE_ENV === "production", // ✅ Only secure in production
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  },
});
app.use(csrfProtection);

// ✅ CSRF Token Route (Frontend Fetches This Token)
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ✅ Serve Static Files
app.use(express.static(path.join(__dirname, "..", "frontend")));

// ✅ Render `index.ejs`
app.get("/", (req, res) => {
  res.render("index", { nonce: res.locals.nonce });
});

// ✅ Authentication Routes
app.use("/api/auth", authRoutes);

// 🛑 Catch 404 for Undefined Routes
app.use((req, res, next) => {
  res.status(404).json({ message: "Route Not Found" });
});

// 🛑 Global Error Handler
app.use((err, req, res, next) => {
  console.error("❌ Server Error:", err.stack);

  // ✅ Handle CSRF Errors
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({ message: "CSRF token validation failed" });
  }

  res.status(500).json({ message: "Internal Server Error" });
});
const allowedOrigins = ["http://localhost:5500", "https://yourdomain.com"];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);
// ✅ Start Server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});

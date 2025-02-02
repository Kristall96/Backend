import csrf from "csurf";
import cookieParser from "cookie-parser";

export const csrfProtection = csrf({ cookie: true });

export const generateCsrfToken = (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
};

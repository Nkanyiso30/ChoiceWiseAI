const express = require("express");
const cors = require("cors");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const OpenAI = require("openai");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const crypto = require("crypto");

require("dotenv").config();
function validateEnvironment() {
  const requiredVariables = ["MONGO_URI", "JWT_SECRET"];

  const missingVariables = requiredVariables.filter((name) => {
    return !process.env[name];
  });

  if (missingVariables.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingVariables.join(", ")}`
    );
  }

  if (
    process.env.NODE_ENV === "production" &&
    process.env.JWT_SECRET.includes("choicewise_super_secret")
  ) {
    throw new Error("JWT_SECRET must be changed before production deployment.");
  }

  if (
    process.env.NODE_ENV === "production" &&
    process.env.JWT_SECRET.length < 32
  ) {
    throw new Error("JWT_SECRET must be at least 32 characters in production.");
  }

  if (!process.env.OPENAI_API_KEY) {
    console.warn("OPENAI_API_KEY is missing. AI fallback mode may be used.");
  }
}

validateEnvironment();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
// Trust proxy for deployment platforms like Render/Railway
app.set("trust proxy", 1);

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

// CORS protection
const allowedOrigins = [
  process.env.CLIENT_URL,
  "http://localhost:5000",
].filter(Boolean);

const corsOptions = {
  credentials: true,
};

if (process.env.NODE_ENV === "production") {
  corsOptions.origin = true;
} else {
  corsOptions.origin = function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  };
}

app.use(cors(corsOptions));

// Body limits
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      if (req.originalUrl === "/api/payments/lemonsqueezy/webhook") {
        req.rawBody = buf;
      }
    },
  })
);

app.use(express.urlencoded({ extended: true, limit: "1mb" }));
// Prevent MongoDB injection patterns
function sanitizeObject(obj) {
  if (!obj || typeof obj !== "object") {
    return;
  }

  for (const key of Object.keys(obj)) {
    const value = obj[key];

    if (key.includes("$") || key.includes(".")) {
      const cleanKey = key.replace(/\$/g, "").replace(/\./g, "");
      obj[cleanKey] = value;
      delete obj[key];

      if (typeof obj[cleanKey] === "object") {
        sanitizeObject(obj[cleanKey]);
      }
    } else if (typeof value === "object") {
      sanitizeObject(value);
    }
  }
}

app.use((req, res, next) => {
  sanitizeObject(req.body);
  sanitizeObject(req.params);
  next();
});

// Rate limits
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: {
    error: "Too many requests. Please wait a few minutes and try again.",
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: {
    error: "Too many login/register attempts. Please wait and try again.",
  },
});

const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: {
    error: "Too many scans. Please wait a few minutes before scanning again.",
  },
});

app.use(generalLimiter);

// Serve frontend files
app.use(express.static(path.join(__dirname, "public")));

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected successfully."))
  .catch((error) => console.error("MongoDB connection error:", error.message));

// User Schema
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    plan: {
      type: String,
      default: "trial",
    },
    trialEndsAt: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    },
    scansUsed: {
  type: Number,
  default: 0,
},
scanLimit: {
  type: Number,
  default: 10,
},
paidScanCredits: {
  type: Number,
  default: 0,
},
paymentProvider: {
  type: String,
  default: null,
},
lemonSqueezyCustomerId: {
  type: String,
  default: null,
},
lemonSqueezyOrderId: {
  type: String,
  default: null,
},
lemonSqueezyVariantId: {
  type: String,
  default: null,
},
lastPurchaseAt: {
  type: Date,
  default: null,
},
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);

// Scan Schema
const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    category: {
  type: String,
  default: "General Message",
},
    messagePreview: {
      type: String,
      required: true,
    },
    riskScore: {
      type: Number,
      required: true,
    },
    riskLevel: {
      type: String,
      required: true,
    },
    redFlags: {
      type: [String],
      default: [],
    },
    recommendation: {
      type: String,
      required: true,
    },
    safeActions: {
  type: [String],
  default: [],
},
confidence: {
  type: String,
  default: "Medium",
},
analysisType: {
  type: String,
  default: "Rule-based",
},
  },
  {
    timestamps: true,
  }
);

const Scan = mongoose.model("Scan", scanSchema);

//trial
function getUserUsage(user) {
  const scansUsed = user.scansUsed || 0;
  const scanLimit = user.scanLimit || 10;
  const paidScanCredits = user.paidScanCredits || 0;

  const trialExpired =
    user.plan === "trial" && new Date(user.trialEndsAt) < new Date();

  const freeScansRemaining = trialExpired
    ? 0
    : Math.max(0, scanLimit - Math.min(scansUsed, scanLimit));

  const totalScansRemaining = freeScansRemaining + paidScanCredits;

  const canScan = totalScansRemaining > 0;

  return {
    plan: user.plan,
    trialEndsAt: user.trialEndsAt,
    scansUsed,
    scanLimit,
    freeScansRemaining,
    paidScanCredits,
    totalScansRemaining,
    trialExpired,
    canScan,
  };
}
// Create JWT token
function createToken(userId) {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
}

// Auth middleware
async function protect(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "You are not logged in. Please login first.",
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(401).json({
        error: "User no longer exists.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token. Please login again.",
    });
  }
}

// Hide sensitive things before saving message preview
function cleanMessageForStorage(message) {
  return message
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[email hidden]")
    .replace(/\+?\d[\d\s-]{7,}\d/g, "[phone hidden]")
    .replace(/\b\d{4,}\b/g, "[number hidden]")
    .slice(0, 180);
}

// Simple rule-based scam checker for Version 1
function analyzeMessage(message) {
  const text = message.toLowerCase();

  const checks = [
    {
      keyword: ["urgent", "immediately", "act now", "limited time"],
      flag: "Creates pressure or urgency",
    },
    {
      keyword: ["otp", "verification code", "pin"],
      flag: "Asks for OTP, PIN, or verification code",
    },
    {
      keyword: ["password", "login details"],
      flag: "Asks for password or login details",
    },
    {
      keyword: ["bank details", "account number", "card number"],
      flag: "Asks for banking or card details",
    },
    {
      keyword: ["pay first", "deposit", "registration fee", "processing fee"],
      flag: "Asks for money before service",
    },
    {
      keyword: ["guaranteed", "100% sure", "no risk"],
      flag: "Makes unrealistic promises",
    },
    {
      keyword: ["click this link", "click here", "verify your account"],
      flag: "Pushes you to click or verify something",
    },
    {
      keyword: ["remote job", "work from home", "high salary"],
      flag: "Possible fake job offer pattern",
    },
  ];

  let redFlags = [];

  checks.forEach((check) => {
    const found = check.keyword.some((word) => text.includes(word));
    if (found) {
      redFlags.push(check.flag);
    }
  });

  let riskScore = 15 + redFlags.length * 12;

  if (riskScore > 95) {
    riskScore = 95;
  }

  let riskLevel = "Low Risk";

  if (riskScore >= 70) {
    riskLevel = "High Risk";
  } else if (riskScore >= 40) {
    riskLevel = "Medium Risk";
  }

  let recommendation = "";

  if (riskLevel === "High Risk") {
    recommendation =
      "Do not trust this message yet. Do not send money, passwords, OTPs, banking details, or personal documents. Verify the sender using an official website or trusted contact.";
  } else if (riskLevel === "Medium Risk") {
    recommendation =
      "Be careful. Some parts look suspicious. Verify the sender before taking action.";
  } else {
    recommendation =
      "No major warning signs were detected, but still be careful before sharing personal or financial information.";
  }

  return {
    riskScore,
    riskLevel,
    redFlags,
    recommendation,
  };
}
//addition function
function hasValidOpenAIKey() {
  return (
    process.env.OPENAI_API_KEY &&
    process.env.OPENAI_API_KEY !== "your_api_key_here"
  );
}

function getOpenAIClient() {
  return new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
  });
}

function extractJson(text) {
  const cleaned = text
    .replace(/```json/g, "")
    .replace(/```/g, "")
    .trim();

  const firstBrace = cleaned.indexOf("{");
  const lastBrace = cleaned.lastIndexOf("}");

  if (firstBrace === -1 || lastBrace === -1) {
    throw new Error("AI did not return valid JSON.");
  }

  const jsonText = cleaned.slice(firstBrace, lastBrace + 1);
  return JSON.parse(jsonText);
}

function normalizeAIResult(data, fallbackResult) {
  let riskScore = Number(data.riskScore);

  if (Number.isNaN(riskScore)) {
    riskScore = fallbackResult.riskScore;
  }

  if (riskScore < 0) riskScore = 0;
  if (riskScore > 100) riskScore = 100;

  let riskLevel = data.riskLevel;

  if (!["Low Risk", "Medium Risk", "High Risk"].includes(riskLevel)) {
    if (riskScore >= 70) {
      riskLevel = "High Risk";
    } else if (riskScore >= 40) {
      riskLevel = "Medium Risk";
    } else {
      riskLevel = "Low Risk";
    }
  }

  return {
    riskScore,
    riskLevel,
    redFlags: Array.isArray(data.redFlags) ? data.redFlags : fallbackResult.redFlags,
    safeActions: Array.isArray(data.safeActions) ? data.safeActions : [],
    recommendation:
      typeof data.recommendation === "string"
        ? data.recommendation
        : fallbackResult.recommendation,
    confidence:
      typeof data.confidence === "string"
        ? data.confidence
        : "Medium",
    analysisType: "AI",
  };
}
async function analyzeMessageWithAI(message, category, fallbackResult) {
  const openai = getOpenAIClient();

  const response = await openai.responses.create({
    model: process.env.OPENAI_MODEL || "gpt-5.4-mini",
    input: [
      {
        role: "system",
        content: `
You are ChoiceWise AI, a safety-focused scam and decision assistant.

Your job is to analyze messages, emails, job offers, online store messages, and suspicious texts.

Return ONLY valid JSON.
No markdown.
No extra explanation outside JSON.
        `,
      },
      {
        role: "user",
        content: `
The user selected this category:

${category}

Analyze this message for scam risk:

"${message}"

Use the category to judge the message properly.

Category guide:
- Job Offer: watch for fake recruiters, payment before employment, unrealistic salary, vague company details, requests for personal documents too early.
- Online Store: watch for fake shops, impossible discounts, suspicious payment methods, no contact details, pressure to buy quickly.
- WhatsApp Message: watch for OTP requests, account verification scams, impersonation, urgent money requests.
- Email: watch for phishing, fake links, fake account alerts, suspicious attachments, password or login requests.
- Contract: explain risky clauses in simple English, but do not pretend to be a lawyer.
- General Message: check for common scam and manipulation patterns.

Return JSON in exactly this format:

{
  "riskScore": 0,
  "riskLevel": "Low Risk",
  "redFlags": ["red flag 1", "red flag 2"],
  "safeActions": ["safe action 1", "safe action 2"],
  "recommendation": "clear recommendation in simple English",
  "confidence": "Low"
}

Rules:
- riskScore must be between 0 and 100.
- riskLevel must be "Low Risk", "Medium Risk", or "High Risk".
- Use simple English.
- If the message asks for OTP, password, bank details, payment first, or creates urgency, increase the risk.
- If there is not enough information, say confidence is Low.
        `,
      },
    ],
  });

  const rawText = response.output_text;
  const parsed = extractJson(rawText);

  return normalizeAIResult(parsed, fallbackResult);
}


async function analyzeMessageSmart(message, category) {
  const fallbackResult = {
    ...analyzeMessage(message),
    safeActions: [
      "Do not share passwords, OTPs, banking details, or personal documents.",
      "Verify the sender using an official website or trusted contact.",
    ],
    confidence: "Medium",
    analysisType: "Rule-based",
  };

  if (!hasValidGeminiKey()) {
    return fallbackResult;
  }

  try {
    return await analyzeMessageWithGemini(message, category, fallbackResult);
  } catch (error) {
    console.error("Gemini analysis failed. Using fallback:");
    console.error("Message:", error.message);

    return {
      ...fallbackResult,
      analysisType: "Rule-based fallback",
    };
  }
}

// Register route
app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email, and password are required.",
      });
    }

    if (password.length < 8) {
  return res.status(400).json({
    error: "Password must be at least 8 characters.",
  });
}

const passwordHasLetter = /[A-Za-z]/.test(password);
const passwordHasNumber = /\d/.test(password);

if (!passwordHasLetter || !passwordHasNumber) {
  return res.status(400).json({
    error: "Password must include at least one letter and one number.",
  });
}

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        error: "This email is already registered. Please login.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const token = createToken(user._id);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user: {
  id: user._id,
  name: user.name,
  email: user.email,
  plan: user.plan,
  trialEndsAt: user.trialEndsAt,
  scansUsed: user.scansUsed,
  scanLimit: user.scanLimit,
},
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to register.",
      details: error.message,
    });
  }
});

// Login route
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    const token = createToken(user._id);

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
  id: user._id,
  name: user.name,
  email: user.email,
  plan: user.plan,
  trialEndsAt: user.trialEndsAt,
  scansUsed: user.scansUsed || 0,
  scanLimit: user.scanLimit || 10,
},
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to login.",
      details: error.message,
    });
  }
});
function sendServerError(res, publicMessage, error) {
  const response = {
    error: publicMessage,
  };

  if (process.env.NODE_ENV !== "production") {
    response.details = error.message;
  }

  return res.status(500).json(response);
}

// Get logged-in user profile
app.get("/api/auth/me", protect, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});
// Get account usage
app.get("/api/account/usage", protect, (req, res) => {
  const usage = getUserUsage(req.user);

  res.json({
    success: true,
    usage,
  });
});
// Get dashboard stats for logged-in user
app.get("/api/dashboard/stats", protect, async (req, res) => {
  try {
   const savedScans = await Scan.countDocuments({
  userId: req.user._id,
});

const totalScans = req.user.scansUsed || 0;

    const highRiskScans = await Scan.countDocuments({
      userId: req.user._id,
      riskLevel: "High Risk",
    });

    const mediumRiskScans = await Scan.countDocuments({
      userId: req.user._id,
      riskLevel: "Medium Risk",
    });

    const lowRiskScans = await Scan.countDocuments({
      userId: req.user._id,
      riskLevel: "Low Risk",
    });

    const usage = getUserUsage(req.user);

    res.json({
      success: true,
      stats: {
  totalScans,
  savedScans,
  highRiskScans,
  mediumRiskScans,
  lowRiskScans,
  usage,
},
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to load dashboard stats.",
      details: error.message,
    });
  }
});
// Upgrade user to Pro - test mode only
app.patch("/api/account/upgrade", protect, async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { plan: "pro" },
      { new: true }
    ).select("-password");

    res.json({
      success: true,
      message: "Account upgraded to Pro successfully. Test mode only.",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        plan: updatedUser.plan,
        trialEndsAt: updatedUser.trialEndsAt,
        scansUsed: updatedUser.scansUsed || 0,
        scanLimit: updatedUser.scanLimit || 10,
      },
      usage: getUserUsage(updatedUser),
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to upgrade account.",
      details: error.message,
    });
  }
});

app.post("/api/payments/lemonsqueezy/checkout", protect, async (req, res) => {
  try {
    if (
      !process.env.LEMONSQUEEZY_API_KEY ||
      !process.env.LEMONSQUEEZY_STORE_ID ||
      !process.env.LEMONSQUEEZY_VARIANT_ID
    ) {
      return res.status(500).json({
        error: "Payment system is not configured yet.",
      });
    }

    const response = await axios.post(
      "https://api.lemonsqueezy.com/v1/checkouts",
      {
        data: {
          type: "checkouts",
          attributes: {
            product_options: {
              redirect_url: `${process.env.CLIENT_URL}/payment-success.html`,
              receipt_button_text: "Go to ChoiceWise AI",
              receipt_link_url: `${process.env.CLIENT_URL}`,
            },
            checkout_data: {
              email: req.user.email,
              custom: {
                user_id: String(req.user._id),
                email: req.user.email,
                product: "ChoiceWise 100 Scan Credits",
              },
            },
          },
          relationships: {
            store: {
              data: {
                type: "stores",
                id: String(process.env.LEMONSQUEEZY_STORE_ID),
              },
            },
            variant: {
              data: {
                type: "variants",
                id: String(process.env.LEMONSQUEEZY_VARIANT_ID),
              },
            },
          },
        },
      },
      {
        headers: {
          Accept: "application/vnd.api+json",
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${process.env.LEMONSQUEEZY_API_KEY}`,
        },
      }
    );

    res.json({
      success: true,
      checkoutUrl: response.data.data.attributes.url,
    });
  } catch (error) {
    console.error(
      "Lemon checkout error:",
      error.response?.data || error.message
    );

    return res.status(500).json({
      error: "Could not start checkout. Please try again.",
    });
  }
});

app.post("/api/payments/lemonsqueezy/webhook", async (req, res) => {
  try {
    const isValidSignature = verifyLemonSqueezySignature(req);

    if (!isValidSignature) {
      return res.status(401).json({
        error: "Invalid webhook signature.",
      });
    }

    const eventName = req.body.meta?.event_name;
    const customData = req.body.meta?.custom_data || {};
    const data = req.body.data;
    const attributes = data?.attributes || {};

    if (eventName !== "order_created") {
      return res.sendStatus(200);
    }

    const userId = customData.user_id;

    if (!userId) {
      console.log("Lemon order webhook received without user_id.");
      return res.sendStatus(200);
    }

    const creditsToAdd = getCreditsPerPurchase();

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        $inc: { paidScanCredits: creditsToAdd },
        $set: {
          plan: "paid",
          paymentProvider: "lemonsqueezy",
          lemonSqueezyOrderId: String(data.id),
          lemonSqueezyCustomerId: String(attributes.customer_id || ""),
          lemonSqueezyVariantId: String(
            attributes.first_order_item?.variant_id ||
              process.env.LEMONSQUEEZY_VARIANT_ID
          ),
          lastPurchaseAt: new Date(),
        },
      },
      { new: true }
    );

    if (!updatedUser) {
      console.log("Lemon order webhook user not found.");
      return res.sendStatus(200);
    }

    console.log(
      `Lemon order_created: added ${creditsToAdd} credits to ${updatedUser.email}`
    );

    return res.sendStatus(200);
  } catch (error) {
    console.error("Lemon webhook error:", error.message);
    return res.sendStatus(500);
  }
});
// Delete all scan data for logged-in user
app.delete("/api/account/data", protect, async (req, res) => {
  try {
    await Scan.deleteMany({
      userId: req.user._id,
    });

    res.json({
      success: true,
      message: "Your scan data has been deleted successfully.",
    });
  } catch (error) {
    return sendServerError(
      res,
      "Failed to delete your scan data. Please try again.",
      error
    );
  }
});

// Delete account permanently
app.delete("/api/account/delete", protect, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        error: "Please enter your password to delete your account.",
      });
    }

    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        error: "Account not found.",
      });
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
      return res.status(401).json({
        error: "Password is incorrect. Account was not deleted.",
      });
    }

    await Scan.deleteMany({
      userId: req.user._id,
    });

    await User.findByIdAndDelete(req.user._id);

    res.json({
      success: true,
      message: "Your account and scan data have been deleted successfully.",
    });
  } catch (error) {
    return sendServerError(
      res,
      "Failed to delete your account. Please try again.",
      error
    );
  }
});

// Analyze and save scan for logged-in user
app.post("/api/analyze", protect, analyzeLimiter, async (req, res) => {
  try {
    const { message, category } = req.body;

const allowedCategories = [
  "General Message",
  "Job Offer",
  "Online Store",
  "WhatsApp Message",
  "Email",
  "Contract",
];

const finalCategory = allowedCategories.includes(category)
  ? category
  : "General Message";

    if (!message || message.trim().length < 5) {
      return res.status(400).json({
        error: "Please enter a longer message to analyze.",
      });
    }
    const usageBeforeScan = getUserUsage(req.user);

if (!usageBeforeScan.canScan) {
  return res.status(403).json({
    error:
      "You have no scans remaining. Please buy more scan credits to continue.",
  });
}

   const result = await analyzeMessageSmart(message, finalCategory);

   const savedScan = await Scan.create({
  userId: req.user._id,
  messagePreview: cleanMessageForStorage(message),
  riskScore: result.riskScore,
  category: finalCategory,
  riskLevel: result.riskLevel,
  redFlags: result.redFlags,
  safeActions: result.safeActions || [],
  recommendation: result.recommendation,
  confidence: result.confidence || "Medium",
  analysisType: result.analysisType || "Rule-based",
});

const userUpdate = {
  $inc: { scansUsed: 1 },
};

if (usageBeforeScan.freeScansRemaining <= 0) {
  userUpdate.$inc.paidScanCredits = -1;
}

const updatedUser = await User.findByIdAndUpdate(
  req.user._id,
  userUpdate,
  { new: true }
).select("-password");

res.json({
  success: true,
  scanId: savedScan._id,
  result: {
    ...result,
    category: finalCategory,
  },
  usage: getUserUsage(updatedUser),
});
  } catch (error) {
    res.status(500).json({
      error: "Failed to analyze message.",
      details: error.message,
    });
  }
});

// Get recent scans for logged-in user only
app.get("/api/history", protect, async (req, res) => {
  try {
    const scans = await Scan.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(8);

    res.json({
      success: true,
      scans,
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to load scan history.",
      details: error.message,
    });
  }
});
// Delete one scan for logged-in user
app.delete("/api/history/:scanId", protect, async (req, res) => {
  try {
    const { scanId } = req.params;

    const deletedScan = await Scan.findOneAndDelete({
      _id: scanId,
      userId: req.user._id,
    });

    if (!deletedScan) {
      return res.status(404).json({
        error: "Scan not found or you do not have permission to delete it.",
      });
    }

    res.json({
      success: true,
      message: "Scan deleted successfully.",
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to delete scan.",
      details: error.message,
    });
  }
});


//helper
function sendServerError(res, publicMessage, error) {
  console.error(publicMessage, error.message);

  const response = {
    error: publicMessage,
  };

  if (process.env.NODE_ENV !== "production") {
    response.details = error.message;
  }

  return res.status(500).json(response);
}
function verifyLemonSqueezySignature(req) {
  const signature = req.headers["x-signature"];

  if (!signature || !req.rawBody || !process.env.LEMONSQUEEZY_WEBHOOK_SECRET) {
    return false;
  }

  const hmac = crypto.createHmac(
    "sha256",
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET
  );

  const digest = Buffer.from(hmac.update(req.rawBody).digest("hex"), "utf8");
  const incomingSignature = Buffer.from(signature, "utf8");

  if (digest.length !== incomingSignature.length) {
    return false;
  }

  return crypto.timingSafeEqual(digest, incomingSignature);
}

function getCreditsPerPurchase() {
  const credits = Number(process.env.CREDITS_PER_PURCHASE || 100);

  if (Number.isNaN(credits) || credits <= 0) {
    return 100;
  }

  return credits;
}


function hasValidGeminiKey() {
  return (
    process.env.GEMINI_API_KEY &&
    process.env.GEMINI_API_KEY !== "your_gemini_api_key_here"
  );
}

async function analyzeMessageWithGemini(message, category, fallbackResult) {
  const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

  const prompt = `
You are ChoiceWise AI, a safety-focused scam and decision assistant.

Analyze this message for scam risk.

Category selected by user:
${category}

Message:
"${message}"

Category guide:
- Job Offer: watch for fake recruiters, payment before employment, unrealistic salary, vague company details, requests for personal documents too early.
- Online Store: watch for fake shops, impossible discounts, suspicious payment methods, no contact details, pressure to buy quickly.
- WhatsApp Message: watch for OTP requests, account verification scams, impersonation, urgent money requests.
- Email: watch for phishing, fake links, fake account alerts, suspicious attachments, password or login requests.
- Contract: explain risky clauses in simple English, but do not pretend to be a lawyer.
- General Message: check for common scam and manipulation patterns.

Return ONLY valid JSON.
No markdown.
No explanation outside JSON.

Return JSON exactly like this:

{
  "riskScore": 0,
  "riskLevel": "Low Risk",
  "redFlags": ["red flag 1", "red flag 2"],
  "safeActions": ["safe action 1", "safe action 2"],
  "recommendation": "clear recommendation in simple English",
  "confidence": "Low"
}

Rules:
- riskScore must be between 0 and 100.
- riskLevel must be "Low Risk", "Medium Risk", or "High Risk".
- Use simple English.
- If the message asks for OTP, password, bank details, payment first, or creates urgency, increase the risk.
- If there is not enough information, confidence should be "Low".
`;

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              {
                text: prompt,
              },
            ],
          },
        ],
      }),
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error?.message || "Gemini API request failed."
    );
  }

  const rawText =
    data.candidates?.[0]?.content?.parts?.[0]?.text || "";

  if (!rawText) {
    throw new Error("Gemini returned an empty response.");
  }

  const parsed = extractJson(rawText);

  return {
    ...normalizeAIResult(parsed, fallbackResult),
    analysisType: "Gemini AI",
  };
}

// Clear all scans for logged-in user
app.delete("/api/history", protect, async (req, res) => {
  try {
    await Scan.deleteMany({
      userId: req.user._id,
    });

    res.json({
      success: true,
      message: "All scan history cleared successfully.",
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to clear history.",
      details: error.message,
    });
  }
});

// Test route
app.get("/api/test", (req, res) => {
  res.json({
    message: "ChoiceWise AI backend is working.",
  });
});

app.get("/api/gemini-test", async (req, res) => {
  try {
    if (!hasValidGeminiKey()) {
      return res.status(400).json({
        success: false,
        error: "GEMINI_API_KEY is missing from .env",
      });
    }

    const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: "Reply with exactly: ChoiceWise Gemini connected.",
                },
              ],
            },
          ],
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "Gemini API test failed.");
    }

    const message =
      data.candidates?.[0]?.content?.parts?.[0]?.text || "";

    res.json({
      success: true,
      model,
      message,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`ChoiceWise AI running on http://localhost:${PORT}`);
});
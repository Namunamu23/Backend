// server.js

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors());
app.use(express.json());

// User Registration Endpoint
app.post("/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  console.log("Incoming registration data:", { firstName, lastName, email });

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, password, is_active) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [firstName, lastName, email, hashedPassword, false]
    );
    const user = result.rows[0];

    // Generate activation token
    const activationToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // Send activation email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    const activationLink = `https://auth-backend-rwsv.onrender.com/activate/${activationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Account Activation",
      text: `Please click the following link to activate your account: ${activationLink}`,
    });

    res.status(201).json({
      message:
        "Registration successful! Please check your email to activate your account.",
    });
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({
        message: "Email is already registered. Please use another email.",
      });
    } else {
      console.error("Registration error:", err);
      res.status(500).json({ message: "Error registering user" });
    }
  }
});

// User Login Endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Incoming login data:", { email });

  try {
    // Check if the user exists
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    // Check if the account is activated
    if (!user.is_active) {
      return res
        .status(403)
        .json({ message: "Account not activated. Please check your email." });
    }

    // If everything is valid
    res.status(200).json({ message: "Login successful" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Error logging in" });
  }
});

// Account Activation Endpoint
app.get("/activate/:token", async (req, res) => {
  const { token } = req.params;

  try {
    // Verify the activation token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    // Activate the user in the database
    const result = await pool.query(
      "UPDATE users SET is_active = true WHERE id = $1 RETURNING email, is_active",
      [userId]
    );

    if (result.rows.length === 0) {
      console.error("Activation failed: Invalid activation token.");
      return res.status(400).send("Invalid activation token.");
    }

    const user = result.rows[0];

    if (user.is_active) {
      console.log(
        `User with email ${user.email} has been successfully activated.`
      );
      // Redirect to login page with email pre-filled
      res.redirect(`${process.env.FRONTEND_URL}/login?email=${user.email}`);
    } else {
      console.error("Activation failed: Unable to update user status.");
      res.status(500).send("Activation failed: Unable to update user status.");
    }
  } catch (err) {
    console.error("Activation error:", err);
    res.status(500).send("Error activating account.");
  }
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});

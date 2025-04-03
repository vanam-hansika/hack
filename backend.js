require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// Import Routes
const authRoutes = require("./routes/authRoutes");
const internshipRoutes = require("./routes/internshipRoutes");
const applicationRoutes = require("./routes/applicationRoutes");

app.use("/api/auth", authRoutes);
app.use("/api/internships", internshipRoutes);
app.use("/api/applications", applicationRoutes);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Database connected"))
    .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ name, email, password: hashedPassword, role });
        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
const express = require("express");
const Internship = require("../models/Internship");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// Create Internship (Only Companies)
router.post("/", authMiddleware, async (req, res) => {
    if (req.user.role !== "company") return res.status(403).json({ message: "Access Denied" });

    try {
        const newInternship = new Internship({ ...req.body, company: req.user.id });
        await newInternship.save();
        res.status(201).json(newInternship);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Get All Internships
router.get("/", async (req, res) => {
    try {
        const internships = await Internship.find().populate("company", "name");
        res.json(internships);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
const express = require("express");
const Application = require("../models/Application");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// Apply for Internship (Only Students)
router.post("/", authMiddleware, async (req, res) => {
    if (req.user.role !== "student") return res.status(403).json({ message: "Access Denied" });

    try {
        const newApplication = new Application({ ...req.body, student: req.user.id });
        await newApplication.save();
        res.status(201).json(newApplication);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Get Applications for an Internship (Only Companies)
router.get("/:internshipId", authMiddleware, async (req, res) => {
    try {
        const applications = await Application.find({ internship: req.params.internshipId }).populate("student", "name");
        res.json(applications);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ["student", "company"], required: true }
});

module.exports = mongoose.model("User", UserSchema);
const mongoose = require("mongoose");

const InternshipSchema = new mongoose.Schema({
    title: String,
    description: String,
    company: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    location: String,
    duration: String
});

module.exports = mongoose.model("Internship", InternshipSchema);
const mongoose = require("mongoose");

const ApplicationSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    internship: { type: mongoose.Schema.Types.ObjectId, ref: "Internship" },
    coverLetter: String
});

module.exports = mongoose.model("Application", ApplicationSchema);
const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Access Denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid Token" });
    }
};

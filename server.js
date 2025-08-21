require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database(process.env.DATABASE, (err) => {
    if (err) {
        console.error("Database error:", err);
    } else {
        console.log("Database connected!");
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)");
    }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Signup route
app.post("/signup", (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        (err) => {
            if (err) {
                console.error(err);
                res.send("Error during signup");
            } else {
                res.send("Signup successful! Now go to Login page.");
            }
        }
    );
});

// Login route
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            res.send("Error while logging in");
        } else if (!user) {
            res.send("User not found");
        } else {
            if (bcrypt.compareSync(password, user.password)) {
                res.redirect(`/welcome.html?user=${encodeURIComponent(username)}`);
            } else {
                res.send("Incorrect password");
            }
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

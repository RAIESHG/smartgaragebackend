var express = require('express');
const auth = require('./authentication/verifytoken');
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

var app = express();
app.use(express.json());
const userRoutes = require('./routes/users');
app.use('/users', userRoutes);

console.log(new Date().toISOString());

app.post("/signup", async (req, res) => {
  try {
    const { name, email, phoneNumber, address, password, role } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (existingUser) {
      return res.status(409).json({ error: "Email is already in use." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { name, email, phoneNumber, address, password: hashedPassword, role },
    });

    res.status(201).json({ message: "User created successfully", newUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// Login API
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid password" });
    }

    res.status(200).json({ message: "Login successful", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to login" });
  }
});

app.use("/",async (req, res) =>{
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
  res.json({
    message: "Welcome to  API"
  });
})
// module.exports = route;

function setHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
}

let port = process.env.PORT || 3000;
app.listen(port, function () {
  return console.log("Started user authentication server listening on port " + port);
});

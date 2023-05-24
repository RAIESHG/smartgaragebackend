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
app.get('/notifications', async (req, res) => {
  try {
    const notifications = await prisma.notification.findMany({
      where: {
        status: 'pending',
      },
    });

    res.status(200).json({ success: true, data: notifications });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching notifications', error: error.message });
  }
});

app.put('/notifications/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const updatedNotification = await prisma.notification.update({
      where: {
        id: Number(id),
      },
      data: {
        status,
      },
    });

    res.status(200).json({ success: true, message: 'Notification updated successfully', data: updatedNotification });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating notification', error: error.message });
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

app.post('/createnotifications', async (req, res) => {
  const { serviceTitle, message, phoneNumber, location, status, userId } = req.body;

  try {
    const newNotification = await prisma.notification.create({
      data: {
        serviceTitle,
        message,
        phoneNumber,
        location,
        status,
        userId
      },
    });

    res.status(201).json({ success: true, message: 'Notification created successfully', data: newNotification });
  } catch (error) {
    console.log(error);

    res.status(500).json({ success: false, message: 'Error creating notification', error: error });
  }
});
app.get('/notifications/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const notifications = await prisma.notification.findMany({
      where: {
        userId: Number(userId),
      },
    });

    res.status(200).json({ success: true, data: notifications });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching notifications', error: error.message });
  }
});


app.get('/users/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: parseInt(id),
      },
     
    });
    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching user details', error: error.message });
  }
});

// Update user details
app.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, phoneNumber, address, password, role } = req.body;

  try {
    const user = await prisma.user.update({
      where: {
        id: Number(id),
      },
      data: {
        name,
        email,
        phoneNumber,
        address,
        password,
        role,
      },
    });

    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating user details', error: error.message });
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

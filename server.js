require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET_BEFORE_PUBLIC_DEPLOYMENT";

const usersFile = path.join(__dirname, "users.json");
const reportsFile = path.join(__dirname, "reports.json");
const blocksFile = path.join(__dirname, "blocks.json");

for (const file of [usersFile, reportsFile, blocksFile]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]");
}

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "100kb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(express.static(path.join(__dirname, "public")));

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function calculateAge(dob) {
  const birth = new Date(`${dob}T00:00:00`);

  if (Number.isNaN(birth.getTime())) return -1;

  const today = new Date();

  let age =
    today.getFullYear() -
    birth.getFullYear();

  if (
    today.getMonth() < birth.getMonth() ||
    (
      today.getMonth() === birth.getMonth() &&
      today.getDate() < birth.getDate()
    )
  ) {
    age--;
  }

  return age;
}

function getUserFromToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = readJSON(usersFile);

    return users.find(
      user => user.id === decoded.userId
    ) || null;
  } catch {
    return null;
  }
}

function publicUser(user) {
  return {
    id: user.id,
    identifier: user.identifier,
    dob: user.dob,
    username: user.username || "",
    bio: user.bio || "",
    notifications: user.notifications !== false,
    createdAt: user.createdAt
  };
}

/* REGISTER */

app.post("/api/register", async (req, res) => {
  try {
    const identifier =
      String(req.body.identifier || "").trim();

    const password =
      String(req.body.password || "");

    const dob =
      String(req.body.dob || "");

    const username =
      String(req.body.username || "")
        .trim()
        .slice(0, 30);

    if (!identifier || !password || !dob) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters."
      });
    }

    const age = calculateAge(dob);

    if (age < 0 || age > 120) {
      return res.status(400).json({
        success: false,
        message: "Invalid date of birth."
      });
    }

    if (age < 18) {
      return res.status(403).json({
        success: false,
        message: "Friend is available only for users aged 18 or older."
      });
    }

    const users = readJSON(usersFile);

    const exists = users.some(
      user =>
        user.identifier.toLowerCase() ===
        identifier.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({
        success: false,
        message: "Account already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = {
      id: Date.now().toString(),
      identifier,
      passwordHash,
      dob,
      username: username || `Friend${Date.now().toString().slice(-4)}`,
      bio: "",
      notifications: true,
      createdAt: new Date().toISOString()
    };

    users.push(user);
    writeJSON(usersFile, users);

    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const identifier =
      String(req.body.identifier || "").trim();

    const password =
      String(req.body.password || "");

    const users = readJSON(usersFile);

    const user = users.find(
      item =>
        item.identifier.toLowerCase() ===
        identifier.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    if (calculateAge(user.dob) < 18) {
      return res.status(403).json({
        success: false,
        message: "This service is for 18+ users only."
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});

/* AUTH MIDDLEWARE */

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  const token =
    header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

  const user =
    getUserFromToken(token);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  req.user = user;
  next();
}

/* CURRENT USER */

app.get("/api/me", auth, (req, res) => {
  res.json({
    success: true,
    user: publicUser(req.user)
  });
});

/* UPDATE PROFILE */

app.patch("/api/profile", auth, (req, res) => {
  const users = readJSON(usersFile);

  const user =
    users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found."
    });
  }

  if (req.body.username !== undefined) {
    user.username =
      String(req.body.username)
        .trim()
        .slice(0, 30);
  }

  if (req.body.bio !== undefined) {
    user.bio =
      String(req.body.bio)
        .trim()
        .slice(0, 250);
  }

  writeJSON(usersFile, users);

  res.json({
    success: true,
    user: publicUser(user)
  });
});

/* SETTINGS */

app.patch("/api/settings", auth, (req, res) => {
  const users = readJSON(usersFile);

  const user =
    users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found."
    });
  }

  if (req.body.notifications !== undefined) {
    user.notifications =
      Boolean(req.body.notifications);
  }

  writeJSON(usersFile, users);

  res.json({
    success: true
  });
});

/* CHANGE PASSWORD */

app.post("/api/change-password", auth, async (req, res) => {
  try {
    const oldPassword =
      String(req.body.oldPassword || "");

    const newPassword =
      String(req.body.newPassword || "");

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "New password must be at least 8 characters."
      });
    }

    const valid =
      await bcrypt.compare(
        oldPassword,
        req.user.passwordHash
      );

    if (!valid) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect."
      });
    }

    const users = readJSON(usersFile);

    const user =
      users.find(u => u.id === req.user.id);

    user.passwordHash =
      await bcrypt.hash(newPassword, 12);

    writeJSON(usersFile, users);

    res.json({
      success: true,
      message: "Password changed successfully."
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});

/* WEBRTC CONFIG */

app.get("/api/webrtc-config", auth, (req, res) => {
  const iceServers = [
    {
      urls: "stun:stun.l.google.com:19302"
    }
  ];

  if (
    process.env.TURN_URL &&
    process.env.TURN_USERNAME &&
    process.env.TURN_CREDENTIAL
  ) {
    iceServers.push({
      urls: process.env.TURN_URL,
      username: process.env.TURN_USERNAME,
      credential: process.env.TURN_CREDENTIAL
    });
  }

  res.json({
    success: true,
    iceServers
  });
});

/* HEALTH */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    app: "Friend",
    status: "online"
  });
});

/* MATCHING */

let waitingUser = null;

function areBlocked(userA, userB) {
  const blocks = readJSON(blocksFile);

  return blocks.some(
    block =>
      (
        block.blocker === userA &&
        block.blocked === userB
      ) ||
      (
        block.blocker === userB &&
        block.blocked === userA
      )
  );
}

function clearWaiting(socketId) {
  if (waitingUser === socketId) {
    waitingUser = null;
  }
}

function disconnectPartner(socket) {
  if (!socket.partner) return;

  const partner =
    io.sockets.sockets.get(socket.partner);

  if (partner) {
    partner.partner = null;
    partner.emit("friend-left");
  }

  socket.partner = null;
}

io.use((socket, next) => {
  const token =
    socket.handshake.auth?.token;

  const user =
    getUserFromToken(token);

  if (!user) {
    return next(
      new Error("Authentication required.")
    );
  }

  if (calculateAge(user.dob) < 18) {
    return next(
      new Error("18+ users only.")
    );
  }

  socket.user = user;
  next();
});

io.on("connection", socket => {

  console.log(
    "User connected:",
    socket.user.identifier
  );

  socket.on("find-friend", () => {

    if (socket.partner) return;

    clearWaiting(socket.id);

    const candidate =
      waitingUser
        ? io.sockets.sockets.get(waitingUser)
        : null;

    if (
      candidate &&
      candidate.id !== socket.id &&
      !candidate.partner &&
      !areBlocked(
        socket.user.id,
        candidate.user.id
      )
    ) {

      waitingUser = null;

      socket.partner = candidate.id;
      candidate.partner = socket.id;

      socket.emit("matched", {
        initiator: true
      });

      candidate.emit("matched", {
        initiator: false
      });

    } else {

      waitingUser = socket.id;

      socket.emit("waiting");
    }
  });

  socket.on("next-friend", () => {

    disconnectPartner(socket);

    clearWaiting(socket.id);

    waitingUser = socket.id;

    socket.emit("waiting");
  });

  socket.on("chat-message", message => {

    if (!socket.partner) return;

    const text =
      String(message || "")
        .trim()
        .slice(0, 500);

    if (!text) return;

    io.to(socket.partner).emit(
      "chat-message",
      text
    );
  });

  socket.on("report-user", data => {

    if (!socket.partner) return;

    const partner =
      io.sockets.sockets.get(socket.partner);

    const reports =
      readJSON(reportsFile);

    reports.push({
      id: Date.now().toString(),
      reporter: socket.user.id,
      reportedUser:
        partner?.user?.id || "unknown",
      reason:
        String(
          data?.reason ||
          "No reason provided"
        )
        .trim()
        .slice(0, 500),
      status: "open",
      createdAt:
        new Date().toISOString()
    });

    writeJSON(reportsFile, reports);

    socket.emit("report-sent");
  });

  socket.on("block-user", () => {

    if (!socket.partner) return;

    const partner =
      io.sockets.sockets.get(socket.partner);

    if (partner) {

      const blocks =
        readJSON(blocksFile);

      const exists =
        blocks.some(
          block =>
            block.blocker === socket.user.id &&
            block.blocked === partner.user.id
        );

      if (!exists) {

        blocks.push({
          blocker: socket.user.id,
          blocked: partner.user.id,
          createdAt:
            new Date().toISOString()
        });

        writeJSON(blocksFile, blocks);
      }

      partner.partner = null;
      partner.emit("blocked-by-user");
    }

    socket.partner = null;

    socket.emit("user-blocked");
  });

  socket.on("signal", data => {

    if (!socket.partner) return;

    io.to(socket.partner).emit(
      "signal",
      data
    );
  });

  socket.on("disconnect", () => {

    clearWaiting(socket.id);

    if (socket.partner) {

      const partner =
        io.sockets.sockets.get(socket.partner);

      if (partner) {
        partner.partner = null;
        partner.emit("friend-left");
      }
    }

    console.log(
      "User disconnected:",
      socket.user.identifier
    );
  });
});

/* ADMIN */

function adminAuth(req, res, next) {
  const key =
    req.headers["x-admin-key"];

  if (
    !process.env.ADMIN_KEY ||
    key !== process.env.ADMIN_KEY
  ) {
    return res.status(403).json({
      success: false,
      message: "Admin access denied."
    });
  }

  next();
}

app.get(
  "/api/admin/reports",
  adminAuth,
  (req, res) => {
    res.json({
      success: true,
      reports: readJSON(reportsFile)
    });
  }
);

app.post(
  "/api/admin/report-status",
  adminAuth,
  (req, res) => {

    const id =
      String(req.body.id || "");

    const status =
      String(req.body.status || "reviewed");

    const reports =
      readJSON(reportsFile);

    const report =
      reports.find(r => r.id === id);

    if (!report) {
      return res.status(404).json({
        success: false,
        message: "Report not found."
      });
    }

    report.status =
      ["open", "reviewed", "closed"]
        .includes(status)
        ? status
        : "reviewed";

    writeJSON(reportsFile, reports);

    res.json({
      success: true
    });
  }
);

/* HOME */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Friend App server running on port ${PORT}`
    );
  }
);

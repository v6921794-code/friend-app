const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "friend-app-change-this-secret";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const usersFile = path.join(__dirname, "users.json");
const reportsFile = path.join(__dirname, "reports.json");
const blocksFile = path.join(__dirname, "blocks.json");

for (const file of [usersFile, reportsFile, blocksFile]) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "[]");
  }
}

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
  const birth = new Date(dob + "T00:00:00");
  const today = new Date();

  if (Number.isNaN(birth.getTime())) {
    return -1;
  }

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
    const decoded =
      jwt.verify(token, JWT_SECRET);

    const users = readJSON(usersFile);

    return users.find(
      user => user.id === decoded.userId
    ) || null;

  } catch {
    return null;
  }
}

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const identifier =
      String(req.body.identifier || "").trim();

    const password =
      String(req.body.password || "");

    const dob =
      String(req.body.dob || "");

    if (!identifier || !password || !dob) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters."
      });
    }

    const age = calculateAge(dob);

    if (age < 0 || age > 120) {
      return res.status(400).json({
        success: false,
        message: "Invalid date of birth."
      });
    }

    /* 18+ SERVER-SIDE AGE RESTRICTION */

    if (age < 18) {
      return res.status(403).json({
        success: false,
        message:
          "Friend is available only for users aged 18 or older."
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
      createdAt:
        new Date().toISOString()
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
      token
    });

  } catch (error) {
    console.error(
      "Register error:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const identifier =
      String(req.body.identifier || "").trim();

    const password =
      String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message:
          "Email/mobile and password are required."
      });
    }

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

    const validPassword =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const age =
      calculateAge(user.dob);

    if (age < 18) {
      return res.status(403).json({
        success: false,
        message:
          "This service is for 18+ users only."
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token
    });

  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});

/* =========================
   SOCKET AUTHENTICATION
========================= */

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

  const age =
    calculateAge(user.dob);

  if (age < 18) {
    return next(
      new Error("18+ users only.")
    );
  }

  socket.user = user;

  next();
});

/* =========================
   MATCHING
========================= */

let waitingUser = null;

function areBlocked(userA, userB) {

  const blocks =
    readJSON(blocksFile);

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

  if (!socket.partner) {
    return;
  }

  const partner =
    io.sockets.sockets.get(
      socket.partner
    );

  if (partner) {
    partner.partner = null;
    partner.emit("friend-left");
  }

  socket.partner = null;
}

io.on("connection", socket => {

  console.log(
    "User connected:",
    socket.id,
    socket.user.identifier
  );

  /* FIND FRIEND */

  socket.on("find-friend", () => {

    if (socket.partner) {
      return;
    }

    clearWaiting(socket.id);

    const waitingSocket =
      waitingUser
        ? io.sockets.sockets.get(
            waitingUser
          )
        : null;

    if (
      waitingSocket &&
      waitingSocket.id !== socket.id &&
      !waitingSocket.partner &&
      !areBlocked(
        socket.user.id,
        waitingSocket.user.id
      )
    ) {

      waitingUser = null;

      socket.partner =
        waitingSocket.id;

      waitingSocket.partner =
        socket.id;

      socket.emit("matched", {
        initiator: true
      });

      waitingSocket.emit("matched", {
        initiator: false
      });

      console.log(
        "Matched:",
        socket.user.identifier,
        "<->",
        waitingSocket.user.identifier
      );

    } else {

      waitingUser =
        socket.id;

      socket.emit("waiting");
    }
  });

  /* NEXT FRIEND */

  socket.on("next-friend", () => {

    disconnectPartner(socket);

    clearWaiting(socket.id);

    waitingUser =
      socket.id;

    socket.emit("waiting");
  });

  /* CHAT */

  socket.on(
    "chat-message",
    message => {

      if (!socket.partner) {
        return;
      }

      const text =
        String(message || "")
          .trim();

      if (
        !text ||
        text.length > 500
      ) {
        return;
      }

      io.to(socket.partner).emit(
        "chat-message",
        text
      );
    }
  );

  /* REPORT */

  socket.on(
    "report-user",
    data => {

      if (!socket.partner) {
        return;
      }

      const partner =
        io.sockets.sockets.get(
          socket.partner
        );

      const reports =
        readJSON(reportsFile);

      reports.push({
        reporter:
          socket.user.id,

        reportedUser:
          partner?.user?.id ||
          "unknown",

        reason:
          String(
            data?.reason ||
            "No reason provided"
          )
          .trim()
          .slice(0, 500),

        createdAt:
          new Date().toISOString()
      });

      writeJSON(
        reportsFile,
        reports
      );

      socket.emit(
        "report-sent"
      );
    }
  );

  /* BLOCK */

  socket.on(
    "block-user",
    () => {

      if (!socket.partner) {
        return;
      }

      const partner =
        io.sockets.sockets.get(
          socket.partner
        );

      if (partner) {

        const blocks =
          readJSON(blocksFile);

        const exists =
          blocks.some(
            block =>
              block.blocker ===
                socket.user.id &&
              block.blocked ===
                partner.user.id
          );

        if (!exists) {

          blocks.push({
            blocker:
              socket.user.id,

            blocked:
              partner.user.id,

            createdAt:
              new Date().toISOString()
          });

          writeJSON(
            blocksFile,
            blocks
          );
        }

        partner.partner =
          null;

        partner.emit(
          "blocked-by-user"
        );
      }

      socket.partner =
        null;

      socket.emit(
        "user-blocked"
      );
    }
  );

  /* WEBRTC SIGNALING */

  socket.on(
    "signal",
    data => {

      if (!socket.partner) {
        return;
      }

      io.to(socket.partner).emit(
        "signal",
        data
      );
    }
  );

  /* DISCONNECT */

  socket.on(
    "disconnect",
    () => {

      clearWaiting(
        socket.id
      );

      if (socket.partner) {

        const partner =
          io.sockets.sockets.get(
            socket.partner
          );

        if (partner) {

          partner.partner =
            null;

          partner.emit(
            "friend-left"
          );
        }
      }

      console.log(
        "User disconnected:",
        socket.id
      );
    }
  );
});

/* =========================
   START SERVER
========================= */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `Friend App server running on port ${PORT}`
    );
  }
);

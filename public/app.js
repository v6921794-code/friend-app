const $ = id => document.getElementById(id);

const authScreen = $("authScreen");
const appScreen = $("app");
const authIdentifier = $("authIdentifier");
const authPassword = $("authPassword");
const authDob = $("authDob");
const dobArea = $("dobArea");
const authButton = $("authButton");
const switchAuth = $("switchAuth");
const authTitle = $("authTitle");
const authMessage = $("authMessage");

const profilePanel = $("profilePanel");
const settingsPanel = $("settingsPanel");
const profileBtn = $("profileBtn");
const settingsBtn = $("settingsBtn");
const closeProfile = $("closeProfile");
const closeSettings = $("closeSettings");

const profileUsername = $("profileUsername");
const profileBio = $("profileBio");
const profileIdentifier = $("profileIdentifier");
const profileDob = $("profileDob");
const saveProfileBtn = $("saveProfileBtn");
const profileMessage = $("profileMessage");

const notificationsToggle = $("notificationsToggle");
const oldPassword = $("oldPassword");
const newPassword = $("newPassword");
const changePasswordBtn = $("changePasswordBtn");
const settingsMessage = $("settingsMessage");
const logoutBtn = $("logoutBtn");

const startBtn = $("startBtn");
const nextBtn = $("nextBtn");
const stopBtn = $("stopBtn");
const micBtn = $("micBtn");
const cameraBtn = $("cameraBtn");

const myVideo = $("myVideo");
const strangerVideo = $("strangerVideo");
const statusBox = $("status");

const messages = $("messages");
const messageInput = $("messageInput");
const sendBtn = $("sendBtn");
const clearBtn = $("clearBtn");
const reportBtn = $("reportBtn");
const blockBtn = $("blockBtn");

let token = localStorage.getItem("friend_token");
let socket = null;
let localStream = null;
let peer = null;
let currentUser = null;
let iceServers = [
  { urls: "stun:stun.l.google.com:19302" }
];
let loginMode = false;

function setStatus(text) {
  statusBox.textContent = text;
}

function showAuth() {
  authScreen.classList.remove("hidden");
  appScreen.classList.add("hidden");
}

function showApp() {
  authScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
}

function addMessage(text, mine = false) {
  const div = document.createElement("div");
  div.className = mine ? "message me" : "message";

  const content = document.createElement("div");
  content.textContent = text;

  const time = document.createElement("span");
  time.className = "message-time";
  time.textContent = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit"
  });

  div.appendChild(content);
  div.appendChild(time);
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function clearMessages() {
  messages.innerHTML = "";
}

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = "Bearer " + token;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  let data = {};

  try {
    data = await response.json();
  } catch {}

  if (!response.ok) {
    throw new Error(data.message || "Request failed.");
  }

  return data;
}

switchAuth.addEventListener("click", () => {
  loginMode = !loginMode;

  if (loginMode) {
    authTitle.textContent = "Login to Friend";
    authButton.textContent = "Login";
    switchAuth.textContent =
      "Don't have an account? Create Account";
    dobArea.classList.add("hidden");
  } else {
    authTitle.textContent = "Create your account";
    authButton.textContent = "Create Account";
    switchAuth.textContent =
      "Already have an account? Login";
    dobArea.classList.remove("hidden");
  }

  authMessage.textContent = "";
});

authButton.addEventListener("click", async () => {
  authMessage.textContent = "Please wait...";

  const identifier = authIdentifier.value.trim();
  const password = authPassword.value;
  const dob = authDob.value;

  if (!identifier || !password) {
    authMessage.textContent =
      "Enter email/mobile and password.";
    return;
  }

  if (!loginMode && !dob) {
    authMessage.textContent =
      "Date of Birth is required.";
    return;
  }

  try {
    const endpoint = loginMode
      ? "/api/login"
      : "/api/register";

    const body = { identifier, password };

    if (!loginMode) {
      body.dob = dob;
    }

    const data = await api(endpoint, {
      method: "POST",
      body: JSON.stringify(body)
    });

    token = data.token;
    currentUser = data.user;

    localStorage.setItem("friend_token", token);

    showApp();

    await loadUser();
    await loadWebRTCConfig();

    connectSocket();

    setStatus("Ready to find a friend.");
    authMessage.textContent = "";
  } catch (error) {
    authMessage.textContent = error.message;
  }
});

async function loadUser() {
  const data = await api("/api/me");
  currentUser = data.user;
  fillProfile();
}

function fillProfile() {
  if (!currentUser) return;

  profileUsername.value = currentUser.username || "";
  profileBio.value = currentUser.bio || "";
  profileIdentifier.value = currentUser.identifier || "";
  profileDob.value = currentUser.dob || "";
  notificationsToggle.checked =
    currentUser.notifications !== false;
}

profileBtn.addEventListener("click", async () => {
  try {
    await loadUser();
  } catch {}

  profilePanel.classList.remove("hidden");
});

settingsBtn.addEventListener("click", async () => {
  try {
    await loadUser();
  } catch {}

  settingsPanel.classList.remove("hidden");
});

closeProfile.addEventListener("click", () => {
  profilePanel.classList.add("hidden");
});

closeSettings.addEventListener("click", () => {
  settingsPanel.classList.add("hidden");
});

saveProfileBtn.addEventListener("click", async () => {
  profileMessage.textContent = "Saving...";

  try {
    const data = await api("/api/profile", {
      method: "PATCH",
      body: JSON.stringify({
        username: profileUsername.value.trim(),
        bio: profileBio.value.trim()
      })
    });

    currentUser = data.user;
    fillProfile();
    profileMessage.textContent = "Profile saved.";
  } catch (error) {
    profileMessage.textContent = error.message;
  }
});

notificationsToggle.addEventListener("change", async () => {
  try {
    await api("/api/settings", {
      method: "PATCH",
      body: JSON.stringify({
        notifications: notificationsToggle.checked
      })
    });

    settingsMessage.textContent = "Settings saved.";
  } catch (error) {
    settingsMessage.textContent = error.message;
  }
});

changePasswordBtn.addEventListener("click", async () => {
  settingsMessage.textContent = "Changing password...";

  try {
    const data = await api("/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        oldPassword: oldPassword.value,
        newPassword: newPassword.value
      })
    });

    settingsMessage.textContent = data.message;
    oldPassword.value = "";
    newPassword.value = "";
  } catch (error) {
    settingsMessage.textContent = error.message;
  }
});

async function loadWebRTCConfig() {
  try {
    const data = await api("/api/webrtc-config");

    if (Array.isArray(data.iceServers)) {
      iceServers = data.iceServers;
    }
  } catch {}
}

async function startCamera() {
  if (localStream) return true;

  try {
    localStream =
      await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true
      });

    myVideo.srcObject = localStream;
    return true;
  } catch {
    setStatus(
      "Camera/microphone permission required."
    );
    return false;
  }
}

function createPeer() {
  if (peer) peer.close();

  peer = new RTCPeerConnection({
    iceServers
  });

  if (localStream) {
    localStream.getTracks().forEach(track => {
      peer.addTrack(track, localStream);
    });
  }

  peer.ontrack = event => {
    if (event.streams[0]) {
      strangerVideo.srcObject = event.streams[0];
    }
  };

  peer.onicecandidate = event => {
    if (event.candidate && socket) {
      socket.emit("signal", {
        type: "candidate",
        candidate: event.candidate
      });
    }
  };

  peer.onconnectionstatechange = () => {
    if (peer.connectionState === "connected") {
      setStatus("Connected with a friend.");
    }

    if (
      peer.connectionState === "failed" ||
      peer.connectionState === "disconnected"
    ) {
      setStatus("Video connection interrupted.");
    }
  };

  return peer;
}

function connectSocket() {
  if (socket) socket.disconnect();

  socket = io({
    auth: { token }
  });

  socket.on("connect", () => {
    setStatus(
      "Connected. Press Start to find a friend."
    );
  });

  socket.on("connect_error", error => {
    setStatus(error.message || "Connection error.");
  });

  socket.on("waiting", () => {
    setStatus("Waiting for a friend...");
  });

  socket.on("matched", async data => {
    clearMessages();
    setStatus("Friend found. Connecting...");

    const ready = await startCamera();
    if (!ready) return;

    createPeer();

    if (data && data.initiator) {
      const offer = await peer.createOffer();
      await peer.setLocalDescription(offer);

      socket.emit("signal", {
        type: "offer",
        offer
      });
    }
  });

  socket.on("signal", async data => {
    try {
      if (!peer) {
        const ready = await startCamera();
        if (!ready) return;
        createPeer();
      }

      if (data.type === "offer") {
        await peer.setRemoteDescription(
          new RTCSessionDescription(data.offer)
        );

        const answer = await peer.createAnswer();
        await peer.setLocalDescription(answer);

        socket.emit("signal", {
          type: "answer",
          answer
        });
      }

      if (data.type === "answer") {
        await peer.setRemoteDescription(
          new RTCSessionDescription(data.answer)
        );
      }

      if (data.type === "candidate" && data.candidate) {
        await peer.addIceCandidate(
          new RTCIceCandidate(data.candidate)
        );
      }
    } catch (error) {
      console.error("WebRTC error:", error);
    }
  });

  socket.on("friend-left", () => {
    if (peer) {
      peer.close();
      peer = null;
    }

    strangerVideo.srcObject = null;
    setStatus(
      "Friend left. Press Next to find another."
    );
  });

  socket.on("chat-message", text => {
    addMessage(text, false);
  });

  socket.on("report-sent", () => {
    alert("Report submitted.");
  });

  socket.on("user-blocked", () => {
    setStatus("User blocked.");
  });

  socket.on("blocked-by-user", () => {
    setStatus(
      "The other user ended the connection."
    );
  });
}

startBtn.addEventListener("click", async () => {
  if (!socket) {
    await loadWebRTCConfig();
    connectSocket();
  }

  const ready = await startCamera();
  if (!ready) return;

  socket.emit("find-friend");
});

nextBtn.addEventListener("click", async () => {
  if (!socket) return;

  if (peer) {
    peer.close();
    peer = null;
  }

  strangerVideo.srcObject = null;
  clearMessages();

  const ready = await startCamera();
  if (!ready) return;

  socket.emit("next-friend");
});

stopBtn.addEventListener("click", () => {
  if (peer) {
    peer.close();
    peer = null;
  }

  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }

  myVideo.srcObject = null;
  strangerVideo.srcObject = null;

  if (socket) {
    socket.disconnect();
    socket = null;
  }

  setStatus("Stopped.");
});

micBtn.addEventListener("click", () => {
  if (!localStream) return;

  const track = localStream.getAudioTracks()[0];
  if (!track) return;

  track.enabled = !track.enabled;

  micBtn.textContent = track.enabled
    ? "🎤 Mic"
    : "🔇 Mic Off";
});

let cameraDevices = [];
let currentCameraIndex = 0;

async function getCameraDevices() {
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    cameraDevices = devices.filter(
      device => device.kind === "videoinput"
    );
  } catch (error) {
    console.error("Camera devices error:", error);
  }
}

async function switchToCamera(index) {
  if (!cameraDevices.length) {
    await getCameraDevices();
  }

  if (!cameraDevices.length) {
    setStatus("No camera found.");
    return;
  }

  currentCameraIndex =
    (index + cameraDevices.length) % cameraDevices.length;

  const device = cameraDevices[currentCameraIndex];

  try {
    const newStream = await navigator.mediaDevices.getUserMedia({
      video: {
        deviceId: { exact: device.deviceId }
      },
      audio: false
    });

    const newTrack = newStream.getVideoTracks()[0];

    if (peer) {
      const sender = peer.getSenders().find(
        s => s.track && s.track.kind === "video"
      );

      if (sender) {
        await sender.replaceTrack(newTrack);
      }
    }

    const oldTrack = localStream?.getVideoTracks()[0];

    if (oldTrack) {
      oldTrack.stop();
    }

    const audioTracks = localStream
      ? localStream.getAudioTracks()
      : [];

    localStream = new MediaStream([
      newTrack,
      ...audioTracks
    ]);

    myVideo.srcObject = localStream;

    const label =
      (device.label || "").toLowerCase();

    if (
      label.includes("back") ||
      label.includes("rear") ||
      label.includes("environment")
    ) {
      cameraBtn.textContent = "📷 Camera On";
      if (backCameraBtn) {
        backCameraBtn.textContent = "📷 Back ✓";
      }
      setStatus("Back camera active.");
    } else {
      cameraBtn.textContent = "📷 Camera On";
      if (backCameraBtn) {
        backCameraBtn.textContent = "📷 Back";
      }
      setStatus("Front camera active.");
    }

  } catch (error) {
    console.error("Camera switch error:", error);
    setStatus("Could not switch camera.");
  }
}

cameraBtn.addEventListener("click", () => {
  if (!localStream) {
    startCamera();
    return;
  }

  const track = localStream.getVideoTracks()[0];

  if (!track) return;

  track.enabled = !track.enabled;

  cameraBtn.textContent = track.enabled
    ? "📷 Camera Off"
    : "📷 Camera On";
});

const backCameraBtn =
  document.getElementById("backCameraBtn");

if (backCameraBtn) {
  backCameraBtn.addEventListener("click", async () => {
    await getCameraDevices();

    if (cameraDevices.length < 2) {
      setStatus("Back camera was not detected.");
      return;
    }

    await switchToCamera(currentCameraIndex + 1);
  });
}
function sendMessage() {
  const text = messageInput.value.trim();

  if (!text || !socket || text.length > 500) return;

  socket.emit("chat-message", text);
  addMessage(text, true);

  messageInput.value = "";
}

sendBtn.addEventListener("click", sendMessage);

messageInput.addEventListener("keydown", event => {
  if (event.key === "Enter") {
    event.preventDefault();
    sendMessage();
  }
});

clearBtn.addEventListener("click", clearMessages);

reportBtn.addEventListener("click", () => {
  if (!socket) return;

  const reason = prompt("Report reason:");

  if (!reason || !reason.trim()) return;

  socket.emit("report-user", {
    reason: reason.trim()
  });
});

blockBtn.addEventListener("click", () => {
  if (!socket) return;

  if (confirm("Block this user and end the connection?")) {
    socket.emit("block-user");
  }
});

function logout() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }

  if (peer) {
    peer.close();
    peer = null;
  }

  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }

  localStorage.removeItem("friend_token");

  token = null;
  currentUser = null;

  myVideo.srcObject = null;
  strangerVideo.srcObject = null;

  showAuth();
}

logoutBtn.addEventListener("click", logout);

async function restoreSession() {
  if (!token) {
    showAuth();
    return;
  }

  try {
    await loadUser();
    await loadWebRTCConfig();

    showApp();
    connectSocket();
  } catch {
    logout();
  }
}

restoreSession();

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}

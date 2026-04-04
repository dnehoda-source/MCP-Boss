# 🐳 Installing Docker — The "Explain It Like I'm 5" Guide

## What Is Docker?

Docker is a box that runs your code the same way everywhere. Your laptop, your coworker's laptop, Google Cloud — same box, same result. No more "it works on my machine."

---

## Step 1: What Computer Are You On?

### 🐧 Linux (Ubuntu/Debian) — Jump to [Linux Install](#linux-install)
### 🍎 Mac — Jump to [Mac Install](#mac-install)
### 🪟 Windows — Jump to [Windows Install](#windows-install)

---

## Linux Install

You're on Linux (I know because I live on your machine 😄). Here's the copy-paste version.

### Step 1: Remove Old Docker (If Any)

Open your terminal and paste this entire block:

```bash
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null
```

**What this does:** Removes any old/broken Docker versions so we start clean.

### Step 2: Install Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
```

**What this does:** Installs the tools Docker needs to download and verify itself.

### Step 3: Add Docker's Official Download Source

```bash
sudo install -m 0755 -d /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

**What this does:** Tells your computer where to download Docker from (Docker's official servers, not some random place).

### Step 4: Install Docker

```bash
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**What this does:** Actually installs Docker. This is the big one.

### Step 5: Let Yourself Run Docker Without `sudo`

```bash
sudo usermod -aG docker $USER
```

**What this does:** Adds you to the "docker" group so you don't have to type `sudo` before every Docker command.

⚠️ **IMPORTANT:** You need to log out and log back in for this to take effect. Or just run:

```bash
newgrp docker
```

### Step 6: Test It

```bash
docker run hello-world
```

**What you should see:**

```
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

🎉 **If you see that, Docker is installed. You're done. Skip to [Next Steps](#next-steps).**

**If you see an error like "permission denied":**
- Did you do Step 5?
- Did you log out and back in?
- Try: `sudo docker run hello-world` (if this works, it's a permissions issue — log out/in)

**If you see "Cannot connect to the Docker daemon":**
```bash
sudo systemctl start docker
sudo systemctl enable docker
```
Then try `docker run hello-world` again.

---

## Mac Install

### Step 1: Download Docker Desktop

Go to: **https://www.docker.com/products/docker-desktop/**

Click the big blue **"Download for Mac"** button.

- **Apple Silicon (M1/M2/M3/M4):** Click "Mac with Apple chip"
- **Intel Mac:** Click "Mac with Intel chip"
- **Not sure which?** Click the Apple menu (🍎 top-left) → "About This Mac" → look for "Chip"

### Step 2: Install It

1. Open the downloaded `.dmg` file
2. Drag the Docker whale icon into the Applications folder
3. Open Docker from Applications
4. It'll ask for your password — type it
5. Wait for it to say "Docker Desktop is running" (green light in the menu bar)

### Step 3: Test It

Open Terminal (search "Terminal" in Spotlight) and type:

```bash
docker run hello-world
```

🎉 **If you see "Hello from Docker!" — you're done. Skip to [Next Steps](#next-steps).**

---

## Windows Install

### Step 1: Check Your Windows Version

- Press `Win + R`, type `winver`, hit Enter
- You need **Windows 10 version 2004 or higher** or **Windows 11**

### Step 2: Enable WSL2 (Windows Subsystem for Linux)

Open **PowerShell as Administrator** (right-click Start → "Terminal (Admin)") and run:

```powershell
wsl --install
```

**Restart your computer when it asks.**

After restart, it'll open a Linux terminal and ask you to create a username/password. Do that.

### Step 3: Download Docker Desktop

Go to: **https://www.docker.com/products/docker-desktop/**

Click **"Download for Windows"**

### Step 4: Install It

1. Run the downloaded installer
2. Check ✅ "Use WSL 2 instead of Hyper-V" (important!)
3. Click "Ok" and let it install
4. Restart your computer if asked

### Step 5: Start Docker Desktop

1. Open Docker Desktop from Start menu
2. Wait for it to say "Docker Desktop is running" (green in the system tray)

### Step 6: Test It

Open PowerShell or Command Prompt and type:

```bash
docker run hello-world
```

🎉 **If you see "Hello from Docker!" — you're done.**

---

## Next Steps

Docker is installed. Now you can build and run the MCP Server locally:

```bash
# Go to the MCP Server folder
cd ~/Desktop/Google_Native_MCP_Server

# Build the container
docker build -t google-native-mcp .

# Run it locally
docker run -p 8080:8080 \
  -e SECOPS_PROJECT_ID="your-project-id" \
  -e SECOPS_CUSTOMER_ID="your-customer-id" \
  -e SECOPS_REGION="us" \
  google-native-mcp

# Test it (in a new terminal)
curl http://localhost:8080/health
```

**For Cloud Run deployment (no local Docker needed):**

Cloud Build builds the container for you in Google's cloud. You don't even need Docker installed locally for that path:

```bash
chmod +x deploy.sh
./deploy.sh
```

---

## Troubleshooting Cheat Sheet

| Problem | Fix |
|---|---|
| `permission denied` | Run `sudo usermod -aG docker $USER` then log out/in |
| `Cannot connect to the Docker daemon` | Run `sudo systemctl start docker` |
| `docker: command not found` | Docker isn't installed — go back to Step 4 |
| Docker Desktop won't start (Mac) | Restart your Mac. Seriously. |
| Docker Desktop won't start (Windows) | Make sure WSL2 is enabled: `wsl --install` then restart |
| `no matching manifest for linux/arm64` | You downloaded the wrong Mac version. Check Intel vs Apple Silicon |
| Build fails with "network timeout" | Your internet connection dropped during build. Try again. |
| `port 8080 already in use` | Something else is using that port. Either stop it or use `-p 9090:8080` instead |

---

## The 30-Second Summary

1. **Linux:** Paste 6 commands. Done.
2. **Mac:** Download app, drag to Applications. Done.
3. **Windows:** Enable WSL2, download app. Done.
4. **Test:** `docker run hello-world`
5. **Build MCP Server:** `docker build -t google-native-mcp .`
6. **Run MCP Server:** `docker run -p 8080:8080 google-native-mcp`

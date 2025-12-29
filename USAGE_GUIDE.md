# SafeOps Network Management - Usage Guide

## 🚀 How to Access the System

### **Step 1: Start All Services**

Run the launcher:
```bash
launch-safeops.bat
```

This starts DHCP Server (50054) + NIC API (8081) + React UI (3001)

**Wait 10-15 seconds** for services to initialize.

---

### **Step 2: Login**

Browser opens at: **http://localhost:3001**

Login with your credentials (default: admin/admin)

---

### **Step 3: Navigate to Network Management**

Click **"Network"** in sidebar:

#### **📊 Overview** (`/network`)
- All network interfaces
- WiFi toggle (iOS-style)
- Hotspot control (📡 button)

#### **🏊 DHCP Server** (`/network/dhcp`) ⭐ **NEW!**
- View 10 DHCP leases
- Search by IP/MAC/hostname
- View pools & stats
- Release leases

---

## 📡 **Hotspot Control**

**Manual Hotspot Support:** ✅ Already implemented!

1. Turn on Windows hotspot manually OR
2. Use UI: Click 📡 button → Start Hotspot

**Status auto-detects** every 10 seconds.

### 📱 **Connected Device Detection**

✅ **NEW!** Mobile devices connected to hotspot are now detected!

When you connect your mobile device to the Windows hotspot:
- View at: **GET http://localhost:8081/api/devices**
- Shows IP (192.168.137.x), MAC address, vendor (Apple/Samsung/etc.)
- Merges with ARP and DHCP data
- Type marked as "hotspot"

See **HOTSPOT_TEST_GUIDE.md** for detailed testing instructions.

---

## 🏊 **DHCP Management Page**

Access: **http://localhost:3001/network/dhcp**

### Features:
- **Leases Tab:** View/search/release leases
- **Pools Tab:** View pool utilization
- **Stats:** Server uptime, active/expired leases

### Mock Data:
10 sample devices (desktop-pc, laptop-work, phone-android, etc.)

---

## 🐛 **Troubleshooting**

### Blank page at localhost:3001?

**Solution:**
1. Start React dev server:
   ```bash
   cd src/ui/dev
   npm run dev
   ```

2. Login first! Go to `/login` then `/network`

Note: Vite runs on port **3001** (configured in vite.config.js)

---

## 📊 **System Status**

✅ DHCP Server running (port 50054)
✅ NIC API running (port 8081)
✅ React UI ready (port **3001**)
✅ Hotspot manual detection working
✅ DHCP UI page added
✅ All features functional

---

**Enjoy!** 🎉

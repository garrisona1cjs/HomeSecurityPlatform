# HomeSecurityPlatform

HomeSecurityPlatform is a lightweight, stateful network security monitoring tool designed to detect new or changing devices on a local network while minimizing alert noise.

This project focuses on **correctness, operational realism, and production-safe behavior**, not just discovery.

---

## 🎯 Project Goals

- Detect **new or changing devices** on a LAN
- Avoid alert spam through **state awareness**
- Reduce noise with **grace-period logic**
- Support **manual trust decisions**
- Maintain **structured, audit-ready logs**
- Behave predictably across restarts

---

## 🧠 Key Design Principles

- **Stateful detection** (not stateless scanning)
- **One-time alerts per condition**
- **UTC-safe time handling**
- **Human-in-the-loop security controls**
- **Separation of concerns**
- **Production hygiene (log rotation, persistence)**

If nothing changes on the network, **nothing alerts**.

---

## 🏗 Architecture Overview


# AideEkopedia

AI-powered multi-session chat application built with **Nuxt 3**, **Pinia**, **Prisma**, **PostgreSQL (Neon)**, and **Logto** for authentication.

---

## 🚀 Features
- Authentication with [Logto](https://logto.dev/) (no password storage required)
- Multi-tab chat sessions
- AI-powered assistant using **Gemini API**
- Messages and sessions stored in PostgreSQL (via Prisma ORM)
- Modern frontend with Nuxt 3, TailwindCSS utility classes, and Pinia store

---

## 📦 Requirements
Before you begin, ensure you have installed:

- **Node.js** ≥ 18
- **pnpm** or **npm** (pnpm recommended)
- **PostgreSQL database** (we use [Neon](https://neon.tech/))
- A **Gemini API key** (free tier works with `gemini-2.5-flash`)
- A **Logto account** (for authentication)

---

## ⚙️ Environment Variables
Create a `.env` file in the root of the project:

```env
# Database
DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DBNAME?schema=public"

# Logto
NUXT_LOGTO_ENDPOINT="https://your-logto-domain"
NUXT_LOGTO_APP_ID="your-logto-app-id"

# AI
GOOGLE_GENERATIVE_AI_API_KEY="your-gemini-api-key"
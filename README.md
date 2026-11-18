# Northstar Inventory Marketplace — React frontend + JavaScript backend

A runnable starter project built from the uploaded inventory-shopping specification. It is intentionally separate from the uploaded E-Kalolsavam React code: those components depend on unrelated festival-specific services, roles and backends.

## Requirements

- Node.js **22.13+** and npm (uses Node's built-in SQLite `node:sqlite`)
- VS Code
- Optional: Google Cloud OAuth Web Client ID for real Google Sign-In
- Optional: SMTP server to send real email-verification messages

## VS Code folder layout

```text
inventory-marketplace/
├── frontend/
│   ├── .env.example             # copy to .env
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── src/
│       ├── main.jsx
│       ├── App.jsx               # landing/login/register/shop
│       └── styles.css
├── backend/
│   ├── .env.example             # copy to .env
│   ├── package.json
│   ├── data/                    # local SQLite DB created at first run
│   └── src/server.js            # Express API, email+Google auth
└── README.md
```

## Run — exact terminal commands

1. Unzip the archive and open the `inventory-marketplace` **folder** in VS Code using **File → Open Folder**.
2. In VS Code choose **Terminal → New Terminal**.
3. In terminal #1:

```bash
cd backend
npm install
# Windows PowerShell: Copy-Item .env.example .env
# macOS/Linux: cp .env.example .env
npm run dev
```

4. Open a **second** VS Code terminal (starting from the project's root folder) and run:

```bash
cd frontend
npm install
# Windows PowerShell: Copy-Item .env.example .env
# macOS/Linux: cp .env.example .env
npm run dev
```

5. Open **http://localhost:5173** in your browser. The Express server runs at **http://localhost:4000**. Check API health at **http://localhost:4000/api/health**.

**Important:** If your second terminal starts in `backend`, run `cd ..` before `cd frontend`.

## First test account

1. Go to **Get started → Register now**.
2. Provide first/last name, email, 10-digit Indian mobile number (starting 6–9) and an **exactly 8-character** password containing upper/lowercase, digit and special character. The 8-character limit follows your uploaded spec; for real production security, permit longer passwords.
3. Submit. In development without SMTP, **the backend terminal prints an email-verification URL**. Open it in your browser.
4. Sign in using the registered email and password. You land at `/shop`.
5. Refresh `/shop` to confirm the session persists; click **Logout** and test that `/shop` redirects to `/login`.

## Google Sign-In (real, optional configuration)

1. In Google Cloud Console, configure an OAuth consent screen and create an **OAuth 2.0 Client ID → Web application**.
2. Add `http://localhost:5173` under **Authorized JavaScript origins**. If in Testing mode, add yourself as a test user.
3. Paste the *same Client ID* into `frontend/.env` as `VITE_GOOGLE_CLIENT_ID=...` and into `backend/.env` as `GOOGLE_CLIENT_ID=...`.
4. Restart frontend and backend. The Google button opens Google's actual account chooser. The backend verifies Google's signed ID token and creates/finds the user.
5. Do not place a Google *client secret* in the frontend; this app needs only the public client ID.

## Real verification emails (optional SMTP configuration)

Set `BACKEND_URL` to the public backend origin if different from localhost. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `backend/.env`, then restart the backend. Without SMTP, a local testing link appears in the terminal. SMTP is **mandatory for production**.

## API route reference

| Method | Route | Description |
|---|---|---|
| GET | `/api/health` | server health |
| POST | `/api/auth/register` | validate and store user; email verification |
| GET | `/api/auth/verify-email?token=...` | verify email and redirect |
| POST | `/api/auth/login` | bcrypt password login |
| POST | `/api/auth/google` | verify Google ID token |
| GET | `/api/auth/me` | current authenticated user |
| POST | `/api/auth/logout` | invalidate session and clear cookie |
| GET | `/api/inventory` | session-protected sample products |

Backend uses Express, bcrypt, a local SQLite database, secure random session tokens stored as SHA-256 hashes, `httpOnly` cookies, an Origin check for state-changing calls and rate limiting. Frontend uses React Router, Vite and a same-origin `/api` development proxy.

## Limits / what is not yet a live shopping service

- Product data is **sample inventory**, not a real product database. Wishlist/cart are local demo interactions; there is no checkout or persistent cart.
- No phone OTP integration (format validation only).
- No password-reset flow or resend-verification endpoint.
- For public deployment, configure HTTPS, SMTP, trusted proxy, stricter production security controls, monitoring and a supported production Node/SQLite deployment. Use an HTTPS `FRONTEND_URL`; adjust cookie/domain/reverse-proxy setup as needed. The project is a development-ready starter, not a fully audited production commerce system.
- The supplied festival pages and associated festival-specific services are **not** migrated; use this as a new project.

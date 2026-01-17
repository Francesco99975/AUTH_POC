# AUTHPOC – Modern Authentication PoC in Go

Responsive Progressive Web App (PWA) authentication system proof-of-concept written in **Golang**.

Clean architecture • JWT + Refresh tokens • 2FA (TOTP) • Email verification • Password reset • Role-based access

## Features

- **User registration** with email verification
- **Login** with username/email + password
- **JWT** access token + long-lived **refresh token** rotation
- **Two-Factor Authentication** (TOTP + backup codes)
- **Password reset** flow
- **Role-based authorization** (USER / ADMIN / DEVELOPER)
- **Responsive frontend** (mobile-first, works well on phones)
- **PWA compliant** (installable, offline-capable basic shell, works offline for login page)
- Uses modern stack with sqlc + PostgreSQL
- Clean separation of concerns (handlers → services → repository)

## Tech Stack

Backend:
- **Go** 1.22+
- **sqlc** (type-safe SQL queries)
- **pgx/v5** (PostgreSQL driver)
- **gorilla/sessions** session auth
- **JWT** (github.com/golang-jwt/jwt/v5)
- **bcrypt** password hashing
- **otpauth** / TOTP (github.com/pquerna/otp)
- **echo** router (lightweight & fast)
- **gommon** logging
- **resend** for emails

Frontend (minimal SPA/PWA):
- **Vanilla JavaScript** + **HTMX** 2.x (hypermedia approach)
- **Alpine.js** (lightweight reactivity)
- **Tailwind CSS** v3 (via CDN + JIT)
- **Vite** (dev server + build – optional)
- **PWA** manifest + Service Worker (basic offline support)

Database:
- **PostgreSQL** 15+

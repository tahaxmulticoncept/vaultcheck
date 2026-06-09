# 🔐 vaultcheck

[![CI](https://github.com/YOUR_USERNAME/vaultcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/vaultcheck/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org)
[![GitHub Achievements](https://img.shields.io/badge/GitHub-Achievements-blueviolet.svg)](https://github.com/YOUR_USERNAME)

> Security auditing tool that scans repos for accidentally committed secrets, API keys, and credentials.

## ✨ Features

- 🔍 20+ detection patterns: AWS keys, GitHub tokens, Stripe keys, Slack tokens, JWT, private keys, DB connection strings, and more
- 📊 Severity-ranked output: CRITICAL → HIGH → MEDIUM → LOW
- 💾 Export findings as JSON for CI pipeline integration
- 🚫 Smart filtering: skips binaries, lockfiles, `.env.example`, `node_modules`
- 🔎 Pinpoints exact file, line number, and code snippet for every finding

## 🚀 Quick Start

```bash
npm install
node src/vaultcheck.js scan .
```

## 📖 Usage

```bash
# Scan current directory
node src/vaultcheck.js scan .

# Scan specific path and export report
node src/vaultcheck.js scan src/ --out report.json

# Audit mode (no non-zero exit on findings)
node src/vaultcheck.js audit .

# List all detection patterns
node src/vaultcheck.js patterns
```

## 🏆 Achievement Scripts

```bash
bash scripts/setup.sh
bash scripts/unlock-all.sh
```

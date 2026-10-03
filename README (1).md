# Deskwork Supply: full-stack store (SQLite version)

Node.js + Express API, SQLite database (a single file, nothing to install), vanilla JS front end.

## Run
1. Install Node.js 18+ from nodejs.org
2. `npm install`
3. `npm start`, then open http://localhost:3000

The `shop.db` file, tables and sample data are created on first start.
Demo admin: `admin@shop.test` / `admin123` (change it). To reset everything, stop the server and delete `shop.db`.
Optional: set the `JWT_SECRET` environment variable to your own long random string.

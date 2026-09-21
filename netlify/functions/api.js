const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const postgres = require("postgres");

function getDb() {
  const connectionString = process.env.NETLIFY_DB_URL;

  if (!connectionString) {
    throw new Error("NETLIFY_DB_URL is not configured.");
  }

  return postgres(connectionString);
}

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      ...extraHeaders
    },
    body: JSON.stringify(body)
  };
}

function parseCookies(event) {
  const header = event.headers?.cookie || event.headers?.Cookie || "";
  const cookies = {};

  header.split(";").forEach((part) => {
    const index = part.indexOf("=");
    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies;
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function getCurrentUser(sql, event) {
  const cookies = parseCookies(event);
  const token = cookies.axh_session;

  if (!token) return null;

  const rows = await sql`
    SELECT u.id, u.name, u.email, u.role, u.balance
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ${token}
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  return rows[0] || null;
}

exports.handler = async (event) => {
  let sql;

  try {
    sql = getDb();

    const path = event.path.replace(/^.*\/api/, "") || "/";
    const method = event.httpMethod;

    let body = {};
    if (event.body) {
      try {
        body = JSON.parse(event.body);
      } catch {
        return json(400, { error: "Invalid JSON." });
      }
    }

    // REGISTER
    if (method === "POST" && path === "/register") {
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!name || !email || password.length < 6) {
        return json(400, {
          error: "Name, email and a password of at least 6 characters are required."
        });
      }

      const existing = await sql`
        SELECT id FROM users WHERE email = ${email} LIMIT 1
      `;

      if (existing.length) {
        return json(409, { error: "An account with that email already exists." });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const rows = await sql`
        INSERT INTO users (name, email, password_hash)
        VALUES (${name}, ${email}, ${passwordHash})
        RETURNING id, name, email, role, balance
      `;

      return json(201, {
        ok: true,
        user: rows[0]
      });
    }

    // LOGIN
    if (method === "POST" && path === "/login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const rows = await sql`
        SELECT id, name, email, password_hash, role, balance
        FROM users
        WHERE email = ${email}
        LIMIT 1
      `;

      if (!rows.length) {
        return json(401, { error: "Invalid email or password." });
      }

      const user = rows[0];
      const valid = await bcrypt.compare(password, user.password_hash);

      if (!valid) {
        return json(401, { error: "Invalid email or password." });
      }

      const token = createSessionToken();

      await sql`
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (${token}, ${user.id}, NOW() + INTERVAL '7 days')
      `;

      return json(
        200,
        {
          ok: true,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            balance: user.balance
          }
        },
        {
          "Set-Cookie": `axh_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
        }
      );
    }

    // LOGOUT
    if (method === "POST" && path === "/logout") {
      const cookies = parseCookies(event);
      const token = cookies.axh_session;

      if (token) {
        await sql`
          DELETE FROM sessions WHERE token = ${token}
        `;
      }

      return json(
        200,
        { ok: true },
        {
          "Set-Cookie":
            "axh_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      );
    }

    // CURRENT USER
    if (method === "GET" && path === "/me") {
      const user = await getCurrentUser(sql, event);

      if (!user) {
        return json(401, { error: "Not authenticated." });
      }

      return json(200, {
        ok: true,
        user
      });
    }

    // TRANSACTIONS
    if (method === "GET" && path === "/transactions") {
      const user = await getCurrentUser(sql, event);

      if (!user) {
        return json(401, { error: "Not authenticated." });
      }

      const rows = await sql`
        SELECT id, type, amount, status, created_at
        FROM transactions
        WHERE user_id = ${user.id}
        ORDER BY created_at DESC
        LIMIT 100
      `;

      return json(200, {
        ok: true,
        transactions: rows
      });
    }

    // DEMONSTRATION MARKET DATA
    if (method === "GET" && path === "/market") {
      return json(200, {
        ok: true,
        demo: true,
        message: "Demonstration market values only.",
        markets: [
          { symbol: "BTC/USD", price: 65000 },
          { symbol: "ETH/USD", price: 3200 },
          { symbol: "EUR/USD", price: 1.08 }
        ]
      });
    }

    // ADMIN: LIST USERS
    if (method === "GET" && path === "/admin/users") {
      const user = await getCurrentUser(sql, event);

      if (!user || user.role !== "admin") {
        return json(403, { error: "Admin access required." });
      }

      const rows = await sql`
        SELECT id, name, email, role, balance, created_at
        FROM users
        ORDER BY created_at DESC
      `;

      return json(200, {
        ok: true,
        users: rows
      });
    }

    // ADMIN: UPDATE BALANCE
    if (method === "POST" && path === "/admin/balance") {
      const user = await getCurrentUser(sql, event);

      if (!user || user.role !== "admin") {
        return json(403, { error: "Admin access required." });
      }

      const userId = Number(body.userId);
      const balance = Number(body.balance);

      if (!Number.isInteger(userId) || !Number.isFinite(balance) || balance < 0) {
        return json(400, { error: "Invalid user ID or balance." });
      }

      const rows = await sql`
        UPDATE users
        SET balance = ${balance}
        WHERE id = ${userId}
        RETURNING id, name, email, role, balance
      `;

      if (!rows.length) {
        return json(404, { error: "User not found." });
      }

      return json(200, {
        ok: true,
        user: rows[0]
      });
    }

    return json(404, { error: "Endpoint not found." });

  } catch (error) {
    console.error("API error:", error);

    return json(500, {
      error: "Something went wrong on the server."
    });
  } finally {
    if (sql) {
      try {
        await sql.end();
      } catch {}
    }
  }
};

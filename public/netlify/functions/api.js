const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { getConnectionString } = require("@netlify/database");
const postgres = require("postgres");

function getDb() {
  return postgres(getConnectionString());
}

function json(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": process.env.URL || "*",
      "Access-Control-Allow-Credentials": "true",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getSessionToken(event) {
  const header = event.headers?.cookie || event.headers?.Cookie || "";

  const match = header.match(/(?:^|;\s*)axh_session=([^;]+)/);

  return match ? match[1] : null;
}

async function getUser(event) {
  const token = getSessionToken(event);

  if (!token) {
    return null;
  }

  const sql = getDb();

  try {
    const rows = await sql`
      SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.balance
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ${token}
        AND s.expires_at > NOW()
      LIMIT 1
    `;

    return rows[0] || null;
  } finally {
    await sql.end();
  }
}

async function createSession(userId) {
  const token = makeToken();

  const sql = getDb();

  try {
    await sql`
      INSERT INTO sessions (
        token,
        user_id,
        expires_at
      )
      VALUES (
        ${token},
        ${userId},
        NOW() + INTERVAL '30 days'
      )
    `;
  } finally {
    await sql.end();
  }

  return token;
}

exports.handler = async (event) => {
  const method = event.httpMethod;
  const path = event.path.replace(/^.*\/api/, "") || "/";

  if (method === "OPTIONS") {
    return json(204, {});
  }

  let body = {};

  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return json(400, {
      error: "Invalid request."
    });
  }

  try {
    // REGISTER
    if (method === "POST" && path === "/register") {
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!name || !email || password.length < 8) {
        return json(400, {
          error: "Please provide your name, a valid email, and a password of at least 8 characters."
        });
      }

      const sql = getDb();

      try {
        const existing = await sql`
          SELECT id
          FROM users
          WHERE email = ${email}
          LIMIT 1
        `;

        if (existing.length) {
          return json(409, {
            error: "An account with that email already exists."
          });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const rows = await sql`
          INSERT INTO users (
            name,
            email,
            password_hash,
            role,
            balance
          )
          VALUES (
            ${name},
            ${email},
            ${passwordHash},
            'user',
            0
          )
          RETURNING id, name, email, role, balance
        `;

        const user = rows[0];

        const token = await createSession(user.id);

        return json(
          201,
          {
            message: "Account created successfully.",
            user
          },
          {
            "Set-Cookie": cookie("axh_session", token, 60 * 60 * 24 * 30)
          }
        );
      } finally {
        await sql.end();
      }
    }

    // LOGIN
    if (method === "POST" && path === "/login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const sql = getDb();

      try {
        const rows = await sql`
          SELECT
            id,
            name,
            email,
            password_hash,
            role,
            balance
          FROM users
          WHERE email = ${email}
          LIMIT 1
        `;

        if (!rows.length) {
          return json(401, {
            error: "Invalid email or password."
          });
        }

        const user = rows[0];

        const valid = await bcrypt.compare(
          password,
          user.password_hash
        );

        if (!valid) {
          return json(401, {
            error: "Invalid email or password."
          });
        }

        const token = await createSession(user.id);

        delete user.password_hash;

        return json(
          200,
          {
            message: "Login successful.",
            user
          },
          {
            "Set-Cookie": cookie("axh_session", token, 60 * 60 * 24 * 30)
          }
        );
      } finally {
        await sql.end();
      }
    }

    // CURRENT USER
    if (method === "GET" && path === "/me") {
      const user = await getUser(event);

      return json(200, {
        user
      });
    }

    // LOGOUT
    if (method === "POST" && path === "/logout") {
      const token = getSessionToken(event);

      if (token) {
        const sql = getDb();

        try {
          await sql`
            DELETE FROM sessions
            WHERE token = ${token}
          `;
        } finally {
          await sql.end();
        }
      }

      return json(
        200,
        {
          message: "Logged out."
        },
        {
          "Set-Cookie": clearCookie("axh_session")
        }
      );
    }

    // TRANSACTIONS
    if (method === "GET" && path === "/transactions") {
      const user = await getUser(event);

      if (!user) {
        return json(401, {
          error: "You must be logged in."
        });
      }

      const sql = getDb();

      try {
        const transactions = await sql`
          SELECT
            id,
            type,
            amount,
            status,
            created_at
          FROM transactions
          WHERE user_id = ${user.id}
          ORDER BY created_at DESC
        `;

        return json(200, {
          transactions
        });
      } finally {
        await sql.end();
      }
    }

    // ADMIN: LIST USERS
    if (method === "GET" && path === "/admin/users") {
      const user = await getUser(event);

      if (!user || user.role !== "admin") {
        return json(403, {
          error: "Admin access required."
        });
      }

      const sql = getDb();

      try {
        const users = await sql`
          SELECT
            id,
            name,
            email,
            role,
            balance,
            created_at
          FROM users
          ORDER BY created_at DESC
        `;

        return json(200, {
          users
        });
      } finally {
        await sql.end();
      }
    }

    // ADMIN: UPDATE BALANCE
    if (method === "POST" && path === "/admin/balance") {
      const user = await getUser(event);

      if (!user || user.role !== "admin") {
        return json(403, {
          error: "Admin access required."
        });
      }

      const userId = Number(body.userId);
      const balance = Number(body.balance);

      if (!Number.isInteger(userId) || !Number.isFinite(balance)) {
        return json(400, {
          error: "Invalid user ID or balance."
        });
      }

      const sql = getDb();

      try {
        const rows = await sql`
          UPDATE users
          SET balance = ${balance}
          WHERE id = ${userId}
          RETURNING id, name, email, role, balance
        `;

        if (!rows.length) {
          return json(404, {
            error: "User not found."
          });
        }

        return json(200, {
          user: rows[0]
        });
      } finally {
        await sql.end();
      }
    }

    // DEMO MARKET DATA
    if (method === "GET" && path === "/market") {
      return json(200, {
        demo: true,
        message: "These are demonstration values, not live market data.",
        markets: [
          {
            symbol: "BTC/USD",
            price: 67420.18,
            change: 2.41
          },
          {
            symbol: "ETH/USD",
            price: 3421.66,
            change: 1.84
          },
          {
            symbol: "EUR/USD",
            price: 1.0842,
            change: 0.32
          },
          {
            symbol: "GOLD",
            price: 2386.4,
            change: -0.18
          }
        ]
      });
    }

    return json(404, {
      error: "API endpoint not found."
    });

  } catch (error) {
    console.error("API error:", error);

    return json(500, {
      error: "Something went wrong on the server."
    });
  }
};

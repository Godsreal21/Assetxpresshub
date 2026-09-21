const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { getConnectionString } = require("@netlify/database");
const postgres = require("postgres");

function db() {
  return postgres(getConnectionString(), {
    ssl: "require"
  });
}

function json(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function cookie(name, value, options = {}) {
  let result = `${name}=${value}`;

  if (options.maxAge !== undefined) {
    result += `; Max-Age=${options.maxAge}`;
  }

  if (options.httpOnly) {
    result += "; HttpOnly";
  }

  if (options.secure) {
    result += "; Secure";
  }

  result += "; SameSite=Lax; Path=/";

  return result;
}

function getToken(event) {
  const header = event.headers?.cookie || "";

  const match = header.match(/axh_session=([^;]+)/);

  return match ? match[1] : null;
}

async function getUser(event) {
  const token = getToken(event);

  if (!token) {
    return null;
  }

  const sql = db();

  try {
    const rows = await sql`
      SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.balance,
        u.created_at
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

exports.handler = async function(event) {
  const method = event.httpMethod;
  const path = (event.path || "").replace(/^\/.netlify\/functions\/api/, "");

  try {
    if (method === "POST" && path === "/register") {
      const body = JSON.parse(event.body || "{}");

      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!name || !email || password.length < 8) {
        return json(400, {
          error: "Please provide your name, a valid email, and a password of at least 8 characters."
        });
      }

      const sql = db();

      try {
        const existing = await sql`
          SELECT id FROM users
          WHERE email = ${email}
          LIMIT 1
        `;

        if (existing.length) {
          return json(409, {
            error: "An account with that email already exists."
          });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const users = await sql`
          INSERT INTO users
            (name, email, password_hash)
          VALUES
            (${name}, ${email}, ${passwordHash})
          RETURNING id, name, email, role, balance, created_at
        `;

        const user = users[0];

        const token = crypto.randomBytes(32).toString("hex");

        await sql`
          INSERT INTO sessions
            (token, user_id, expires_at)
          VALUES
            (${token}, ${user.id}, NOW() + INTERVAL '30 days')
        `;

        return json(
          201,
          { user },
          {
            "Set-Cookie": cookie("axh_session", token, {
              maxAge: 60 * 60 * 24 * 30,
              httpOnly: true,
              secure: true
            })
          }
        );
      } finally {
        await sql.end();
      }
    }

    if (method === "POST" && path === "/login") {
      const body = JSON.parse(event.body || "{}");

      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!email || !password) {
        return json(400, {
          error: "Email and password are required."
        });
      }

      const sql = db();

      try {
        const users = await sql`
          SELECT *
          FROM users
          WHERE email = ${email}
          LIMIT 1
        `;

        if (!users.length) {
          return json(401, {
            error: "Invalid email or password."
          });
        }

        const user = users[0];

        const valid = await bcrypt.compare(
          password,
          user.password_hash
        );

        if (!valid) {
          return json(401, {
            error: "Invalid email or password."
          });
        }

        const token = crypto.randomBytes(32).toString("hex");

        await sql`
          INSERT INTO sessions
            (token, user_id, expires_at)
          VALUES
            (${token}, ${user.id}, NOW() + INTERVAL '30 days')
        `;

        delete user.password_hash;

        return json(
          200,
          { user },
          {
            "Set-Cookie": cookie("axh_session", token, {
              maxAge: 60 * 60 * 24 * 30,
              httpOnly: true,
              secure: true
            })
          }
        );
      } finally {
        await sql.end();
      }
    }

    if (method === "POST" && path === "/logout") {
      const token = getToken(event);

      if (token) {
        const sql = db();

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
        { success: true },
        {
          "Set-Cookie": cookie("axh_session", "", {
            maxAge: 0,
            httpOnly: true,
            secure: true
          })
        }
      );
    }

    if (method === "GET" && path === "/me") {
      const user = await getUser(event);

      return json(200, {
        user
      });
    }

    if (method === "GET" && path === "/transactions") {
      const user = await getUser(event);

      if (!user) {
        return json(401, {
          error: "Not logged in."
        });
      }

      const sql = db();

      try {
        const transactions = await sql`
          SELECT id, type, amount, status, created_at
          FROM transactions
          WHERE user_id = ${user.id}
          ORDER BY created_at DESC
          LIMIT 100
        `;

        return json(200, {
          transactions
        });
      } finally {
        await sql.end();
      }
    }

    if (method === "GET" && path === "/admin/users") {
      const user = await getUser(event);

      if (!user || user.role !== "admin") {
        return json(403, {
          error: "Admin access required."
        });
      }

      const sql = db();

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

    if (method === "POST" && path === "/admin/balance") {
      const user = await getUser(event);

      if (!user || user.role !== "admin") {
        return json(403, {
          error: "Admin access required."
        });
      }

      const body = JSON.parse(event.body || "{}");

      const userId = Number(body.userId);
      const amount = Number(body.amount);

      if (!Number.isInteger(userId) || !Number.isFinite(amount)) {
        return json(400, {
          error: "Invalid user ID or amount."
        });
      }

      const sql = db();

      try {
        const rows = await sql`
          UPDATE users
          SET balance = balance + ${amount}
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

    if (method === "GET" && path === "/market") {
      return json(200, {
        demo: true,
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
      error: "Endpoint not found."
    });

  } catch (error) {
    console.error(error);

    return json(500, {
      error: "Server error."
    });
  }
};

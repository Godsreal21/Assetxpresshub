const postgres = require("postgres");

exports.handler = async () => {
  try {
    const connectionString = process.env.NETLIFY_DB_URL;

    if (!connectionString) {
      return {
        statusCode: 500,
        body: JSON.stringify({
          ok: false,
          error: "NETLIFY_DB_URL is not configured"
        })
      };
    }

    const sql = postgres(connectionString);
    const result = await sql`SELECT NOW() AS connected_at`;
    await sql.end();

    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true,
        message: "Database connection works",
        connected_at: result[0].connected_at
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        ok: false,
        error: error.message
      })
    };
  }
};

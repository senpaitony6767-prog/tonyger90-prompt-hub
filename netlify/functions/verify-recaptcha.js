
exports.handler = async function (event) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ success: false })
    };
  }

  const secret = process.env.RECAPTCHA_SECRET_KEY;

  if (!secret) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: "Server verification is not configured"
      })
    };
  }

  let body;

  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false })
    };
  }

  if (typeof body.token !== "string" || !body.token) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false })
    };
  }

  try {
    const params = new URLSearchParams({
      secret,
      response: body.token
    });

    const verifyResponse = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: params.toString()
      }
    );

    const result = await verifyResponse.json();

    const success =
      result.success === true &&
      result.hostname === "promptslov2.netlify.app";

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success })
    };
  } catch {
    return {
      statusCode: 502,
      headers,
      body: JSON.stringify({
        success: false,
        error: "Google verification unavailable"
      })
    };
  }
};

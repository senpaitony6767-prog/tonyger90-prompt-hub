const admin = require("firebase-admin");

function getAdmin() {
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error("Missing FIREBASE_SERVICE_ACCOUNT environment variable.");
    admin.initializeApp({
      credential: admin.credential.cert(JSON.parse(raw)),
      databaseURL: process.env.FIREBASE_DATABASE_URL
    });
  }
  return admin;
}

async function verifyRequest(event) {
  const a = getAdmin();
  const header = event.headers.authorization || event.headers.Authorization || "";
  const match = header.match(/^Bearer (.+)$/i);
  if (!match) throw new Error("Authentication required.");
  const decoded = await a.auth().verifyIdToken(match[1]);
  if (!decoded.email_verified) throw new Error("Verified email required.");
  return { admin: a, user: decoded };
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: {"Content-Type":"application/json", "Cache-Control":"no-store"},
    body: JSON.stringify(body)
  };
}

module.exports = {getAdmin, verifyRequest, response};

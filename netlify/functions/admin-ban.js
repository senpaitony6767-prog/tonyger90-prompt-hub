const { verifyUser, response } = require("./firebase-admin");
const ADMIN_UID = "vUMzFkWq5TaTV6ftv5q8TyFatqf1";
exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return response(405, { error: "Method not allowed." });
  try {
    const { admin, decoded } = await verifyUser(event);
    if (decoded.uid !== ADMIN_UID) return response(403, { error: "Admin access required." });
    const body = JSON.parse(event.body || "{}"), db = admin.database();
    if (body.action === "list") {
      const snap = await db.ref("bans").once("value"), all = snap.val() || {};
      const records = Object.entries(all).filter(([uid,b]) => b && b.active === true && (b.permanent || !b.expiresAt || Date.now() < b.expiresAt)).map(([uid,b]) => ({ uid, ...b })).slice(0,100);
      return response(200, { records });
    }
    if (body.action === "history") {
      const snap = await db.ref("banHistory").once("value");
      const history = Object.values(snap.val() || {})
        .sort((a, b) => (Number(b.createdAt || b.at || 0) - Number(a.createdAt || a.at || 0)))
        .slice(0, 100);
      return response(200, { history });
    }
    const uid = String(body.uid || "").trim();
    if (!uid || uid === ADMIN_UID || uid.length > 128) return response(400, { error: "Enter a valid non-admin Firebase UID." });
    if (body.action === "unban") {
      await db.ref("bans/" + uid).update({ active: false, unbannedAt: Date.now(), unbannedBy: decoded.uid });
      await db.ref("banHistory").push({ uid, action: "unban", at: Date.now(), by: decoded.uid });
      return response(200, { ok: true });
    }
    if (body.action === "ban") {
      const duration = String(body.duration || ""), reason = String(body.reason || "").trim().slice(0,180);
      if (!reason) return response(400, { error: "A ban reason is required." });
      if (!["7","30","permanent"].includes(duration)) return response(400, { error: "Choose 7 days, 30 days, or permanent." });
      const createdAt = Date.now(), permanent = duration === "permanent", durationDays = permanent ? null : Number(duration);
      const record = { active: true, permanent, durationDays, reason, createdAt, expiresAt: permanent ? null : createdAt + durationDays * 86400000, source: "admin", createdBy: decoded.uid };
      await db.ref("bans/" + uid).set(record);
      await db.ref("banHistory").push({ uid, ...record });
      return response(200, { ok: true });
    }
    return response(400, { error: "Unknown admin action." });
  } catch (e) { return response(401, { error: e.message || "Admin request failed." }); }
};

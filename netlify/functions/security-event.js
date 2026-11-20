const {verifyRequest, response} = require("./firebase-admin");

const WINDOW_MS = 10 * 60 * 1000;
const DAY = 24 * 60 * 60 * 1000;

// Conservative thresholds: only repeated server-received reports can trigger
// a temporary ban. Permanent bans are deliberately admin-only.
exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return response(405, {error:"Method not allowed"});
  try {
    const {admin, user} = await verifyRequest(event);
    if (user.uid === process.env.ADMIN_UID) return response(200, {ok:true});
    let payload = {};
    try { payload = JSON.parse(event.body || "{}"); } catch (_) {}
    const allowed = new Set(["failed_login"]);
    if (!allowed.has(payload.type)) return response(400, {error:"Unsupported event"});
    const ref = admin.database().ref("security/events/" + user.uid);
    const now = Date.now();
    const result = await ref.transaction(old => {
      const current = old && typeof old === "object" ? old : {timestamps:[]};
      const timestamps = (Array.isArray(current.timestamps) ? current.timestamps : [])
        .filter(t => Number(t) > now - WINDOW_MS);
      timestamps.push(now);
      return {timestamps:timestamps.slice(-30), updatedAt:now};
    });
    const count = (result.snapshot.val().timestamps || []).length;
    const banRef = admin.database().ref("security/bans/" + user.uid);
    const banSnap = await banRef.get();
    const existing = banSnap.val();
    if (existing && existing.active && (existing.permanent || Number(existing.until || 0) > now)) {
      return response(200, {ok:true, banned:true});
    }

    // 6 or more failed-login reports in 10 minutes => 7-day access suspension.
    // A later repeat after the first temporary ban has expired => 30 days.
    if (count >= 6) {
      const priorCount = Number((existing && existing.banCount) || 0);
      const duration = priorCount >= 1 ? 30 * DAY : 7 * DAY;
      await banRef.set({
        active:true, permanent:false, reason:"Repeated failed sign-in attempts",
        startedAt:now, until:now + duration, banCount:priorCount + 1,
        source:"automated-security"
      });
      await ref.remove();
      return response(200, {ok:true, banned:true});
    }
    return response(200, {ok:true, suspiciousCount:count});
  } catch (e) {
    return response(401, {error:e.message || "Security event rejected"});
  }
};

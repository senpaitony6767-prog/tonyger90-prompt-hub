const {verifyRequest, response} = require("./firebase-admin");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return response(405, {error:"Method not allowed"});
  try {
    const {admin, user} = await verifyRequest(event);
    if (user.uid === process.env.ADMIN_UID) return response(200, {banned:false});
    const snap = await admin.database().ref("security/bans/" + user.uid).get();
    const ban = snap.val();
    if (!ban || !ban.active) return response(200, {banned:false});
    if (!ban.permanent && Number(ban.until || 0) <= Date.now()) {
      await snap.ref.update({active:false, expiredAt:Date.now()});
      return response(200, {banned:false});
    }
    return response(200, {banned:true, ban:{
      reason: String(ban.reason || "Suspicious activity detected."),
      permanent: !!ban.permanent,
      until: Number(ban.until || 0)
    }});
  } catch (e) {
    return response(401, {error:e.message || "Security check failed"});
  }
};

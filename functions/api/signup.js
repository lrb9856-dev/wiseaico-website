// Cloudflare Pages Function — handles POST /api/signup
// Saves launch-page signups straight into the "wiseaico-signups" D1 database.
// Requires a D1 binding named DB on the Pages project (Settings > Bindings).

export async function onRequestPost(context) {
  const { request, env } = context;

  let data;
  try {
    data = await request.json();
  } catch (err) {
    return json({ ok: false, error: "Please fill out the form and try again." }, 400);
  }

  const name = clean(data.name, 200);
  const email = clean(data.email, 320);
  const work = clean(data.work, 200);
  const honeypot = clean(data.company_website, 200); // hidden field — real visitors never fill it in

  // Bots that fill every field (including hidden ones) get a fake "success" so they move on.
  if (honeypot) {
    return json({ ok: true });
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || !email || !work || !emailPattern.test(email)) {
    return json({ ok: false, error: "Please fill in all three fields with a valid email." }, 400);
  }

  if (!env.DB) {
    return json({ ok: false, error: "Signups aren't set up yet — please try again shortly." }, 500);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO signups (name, email, work) VALUES (?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET name = excluded.name, work = excluded.work`
    ).bind(name, email, work).run();
  } catch (err) {
    return json({ ok: false, error: "Something went wrong saving your info. Please try again." }, 500);
  }

  return json({ ok: true });
}

// Anything other than POST (including a browser navigating straight to the URL) gets a plain 405.
export async function onRequestGet() {
  return json({ ok: false, error: "Method not allowed." }, 405);
}

function clean(value, maxLength) {
  return (typeof value === "string" ? value : "").trim().slice(0, maxLength);
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { "Content-Type": "application/json" }
  });
}

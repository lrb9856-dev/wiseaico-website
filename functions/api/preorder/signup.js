// Cloudflare Pages Function — handles POST /api/preorder/signup
//
// Creates a pending preorder account (name/email/password) for the "buy 6
// months, get 6 months free" Unlimited All-Access deal, then starts a
// Stripe Checkout Session for the $222 one-time charge. The frontend
// redirects the browser to the returned URL to collect payment.
//
// Requires:
//   - D1 binding named DB (same wiseaico-signups database as /api/signup)
//   - env.STRIPE_SECRET_KEY  — Stripe secret key (test or live)
//   - env.STRIPE_PRICE_ID    — the $222 one-time Price ID from Stripe
//
// The password is never stored in plain text — it's hashed with PBKDF2
// (100,000 iterations, SHA-256, random salt per account) before it touches D1.

export async function onRequestPost(context) {
  const { request, env } = context;

  let data;
  try {
    data = await request.json();
  } catch (err) {
    return json({ ok: false, error: "Please fill out the form and try again." }, 400);
  }

  const name = clean(data.name, 200);
  const email = clean(data.email, 320).toLowerCase();
  const password = typeof data.password === "string" ? data.password : "";
  const honeypot = clean(data.company_website, 200); // hidden field — real visitors never fill it in

  // Bots that fill every field (including hidden ones) get a fake "success" so they move on.
  if (honeypot) {
    return json({ ok: true, url: null });
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || !email || !emailPattern.test(email)) {
    return json({ ok: false, error: "Please enter your name and a valid email." }, 400);
  }
  if (password.length < 8) {
    return json({ ok: false, error: "Password must be at least 8 characters." }, 400);
  }

  if (!env.DB || !env.STRIPE_SECRET_KEY || !env.STRIPE_PRICE_ID) {
    return json({ ok: false, error: "Preorders aren't set up yet — please try again shortly." }, 500);
  }

  // Don't let someone "re-buy" on an email that already has a confirmed preorder.
  try {
    const existing = await env.DB.prepare(
      "SELECT status FROM preorder_accounts WHERE email = ?"
    ).bind(email).first();
    if (existing && existing.status === "paid") {
      return json({ ok: false, error: "This email already has an active preorder." }, 409);
    }
  } catch (err) {
    return json({ ok: false, error: "Something went wrong. Please try again." }, 500);
  }

  const passwordHash = await hashPassword(password);

  let session;
  try {
    session = await createCheckoutSession(env, email);
  } catch (err) {
    return json({ ok: false, error: "Couldn't start checkout. Please try again." }, 502);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO preorder_accounts (name, email, password_hash, stripe_checkout_session_id, status)
       VALUES (?, ?, ?, ?, 'pending')
       ON CONFLICT(email) DO UPDATE SET
         name = excluded.name,
         password_hash = excluded.password_hash,
         stripe_checkout_session_id = excluded.stripe_checkout_session_id
       WHERE preorder_accounts.status != 'paid'`
    ).bind(name, email, passwordHash, session.id).run();
  } catch (err) {
    return json({ ok: false, error: "Something went wrong saving your info. Please try again." }, 500);
  }

  return json({ ok: true, url: session.url });
}

// Anything other than POST (including a browser navigating straight to the URL) gets a plain 405.
export async function onRequestGet() {
  return json({ ok: false, error: "Method not allowed." }, 405);
}

async function createCheckoutSession(env, email) {
  const params = new URLSearchParams();
  params.set("mode", "payment");
  params.set("line_items[0][price]", env.STRIPE_PRICE_ID);
  params.set("line_items[0][quantity]", "1");
  params.set("customer_email", email);
  params.set("success_url", "https://wiseaico.com/preorder-success.html?session_id={CHECKOUT_SESSION_ID}");
  params.set("cancel_url", "https://wiseaico.com/?preorder=cancelled");
  params.set("metadata[email]", email);

  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Stripe error: ${errText}`);
  }

  return res.json();
}

// PBKDF2-SHA256, 100k iterations, random 16-byte salt per account.
// Stored as "pbkdf2$<iterations>$<salt-base64>$<hash-base64>" in one column.
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const iterations = 100000;
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return `pbkdf2$${iterations}$${bufferToBase64(salt.buffer)}$${bufferToBase64(bits)}`;
}

function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
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

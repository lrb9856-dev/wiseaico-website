// Cloudflare Pages Function — handles POST /api/preorder/webhook
//
// Stripe calls this after a checkout.session.completed event. Verifies the
// request really came from Stripe (HMAC signature check, no SDK needed),
// then marks the matching preorder_accounts row as paid.
//
// Requires:
//   - D1 binding named DB
//   - env.STRIPE_WEBHOOK_SECRET — the signing secret shown on this endpoint's
//     page in the Stripe dashboard (Developers > Webhooks > this endpoint)

export async function onRequestPost(context) {
  const { request, env } = context;

  const sigHeader = request.headers.get("stripe-signature");
  const rawBody = await request.text(); // must read as raw text — signature is over the exact bytes

  if (!env.STRIPE_WEBHOOK_SECRET) {
    return new Response("Webhook not configured", { status: 500 });
  }

  const valid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    return new Response("Invalid signature", { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    return new Response("Bad payload", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data && event.data.object;
    if (session && env.DB) {
      const email = (session.customer_details && session.customer_details.email) || null;
      const paymentIntentId = session.payment_intent || null;
      const customerId = session.customer || null;
      const amountTotal = session.amount_total || null;

      try {
        await env.DB.prepare(
          `UPDATE preorder_accounts
           SET status = 'paid',
               stripe_customer_id = ?,
               stripe_payment_intent_id = ?,
               amount_paid_cents = ?,
               paid_at = datetime('now')
           WHERE stripe_checkout_session_id = ?
              OR (email = ? AND status != 'paid')`
        ).bind(customerId, paymentIntentId, amountTotal, session.id, email).run();
      } catch (err) {
        // Ack the webhook anyway so Stripe doesn't retry forever — if a payment doesn't
        // show up as 'paid' in D1, check the Stripe dashboard and this table by hand.
      }
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

export async function onRequestGet() {
  return new Response("Method not allowed", { status: 405 });
}

// Reimplements Stripe's documented webhook signature check (HMAC-SHA256 of
// "{timestamp}.{raw body}" using the endpoint's signing secret) since the
// Stripe SDK's own verifier needs a Node crypto API that isn't available here.
async function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader) return false;

  const parts = {};
  sigHeader.split(",").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    parts[pair.slice(0, idx)] = pair.slice(idx + 1);
  });

  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return false;

  // Reject stale signatures (5 minute tolerance) to guard against replay.
  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 300) return false;

  const signedPayload = `${timestamp}.${rawBody}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, enc.encode(signedPayload));
  const computedHex = bufferToHex(sigBuffer);

  if (computedHex.length !== v1.length) return false;
  let mismatch = 0;
  for (let i = 0; i < computedHex.length; i++) {
    mismatch |= computedHex.charCodeAt(i) ^ v1.charCodeAt(i);
  }
  return mismatch === 0;
}

function bufferToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

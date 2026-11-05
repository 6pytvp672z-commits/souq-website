import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, btcpay-sig",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const maximumBodySize = 64 * 1024;
const handledEvents = new Set([
  "InvoiceSettled",
  "InvoiceExpired",
  "InvoiceInvalid",
  "InvoiceProcessing",
  "InvoiceReceivedPayment",
]);

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function requiredEnvironment(name: string) {
  return Deno.env.get(name)?.trim() || null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function constantTimeEqual(left: string, right: string) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

async function verifySignature(
  body: Uint8Array,
  header: string | null,
  secret: string,
) {
  const signature = header?.trim().match(/^sha256=([a-f0-9]{64})$/i)?.[1];
  if (!signature) return false;
  const secretBytes = new TextEncoder().encode(secret);
  const secretBuffer = new ArrayBuffer(secretBytes.byteLength);
  new Uint8Array(secretBuffer).set(secretBytes);
  const bodyBuffer = new ArrayBuffer(body.byteLength);
  new Uint8Array(bodyBuffer).set(body);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, bodyBuffer),
  );
  return constantTimeEqual(toHex(digest), signature.toLowerCase());
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed." }, 405);
  }

  const serviceRoleKey = requiredEnvironment("SUPABASE_SERVICE_ROLE_KEY");
  const supabaseUrl = requiredEnvironment("SUPABASE_URL");
  const storeId = requiredEnvironment("BTCPAY_STORE_ID");
  const webhookSecret = requiredEnvironment("BTCPAY_WEBHOOK_SECRET");
  if (!serviceRoleKey || !supabaseUrl || !storeId || !webhookSecret) {
    console.error(
      "BTCPay webhook is missing one or more required server-side settings.",
    );
    return jsonResponse({ error: "Webhook is not configured." }, 503);
  }

  const contentLength = Number(request.headers.get("content-length") || "0");
  if (Number.isFinite(contentLength) && contentLength > maximumBodySize) {
    return jsonResponse({ error: "Webhook body is too large." }, 413);
  }

  let body: Uint8Array;
  try {
    body = new Uint8Array(await request.arrayBuffer());
  } catch (error) {
    console.error("Could not read the BTCPay webhook body.", error);
    return jsonResponse({ error: "Could not read webhook body." }, 400);
  }
  if (body.byteLength > maximumBodySize) {
    return jsonResponse({ error: "Webhook body is too large." }, 413);
  }

  let signatureIsValid: boolean;
  try {
    signatureIsValid = await verifySignature(
      body,
      request.headers.get("BTCPay-Sig"),
      webhookSecret,
    );
  } catch (error) {
    console.error("Could not verify the BTCPay webhook signature.", error);
    return jsonResponse({ error: "Could not verify webhook signature." }, 500);
  }
  if (!signatureIsValid) {
    return jsonResponse({ error: "Invalid webhook signature." }, 401);
  }

  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return jsonResponse({ error: "Webhook body must be valid JSON." }, 400);
  }
  if (
    !isRecord(payload) ||
    typeof payload.type !== "string" ||
    typeof payload.invoiceId !== "string" ||
    typeof payload.storeId !== "string"
  ) {
    return jsonResponse({
      error: "Webhook is missing required invoice details.",
    }, 400);
  }
  if (payload.storeId !== storeId) {
    return jsonResponse({ error: "Webhook store does not match." }, 400);
  }
  if (!handledEvents.has(payload.type)) {
    return jsonResponse({ ok: true, ignored: true });
  }
  if (
    (payload.type === "InvoiceExpired" &&
      typeof payload.partiallyPaid !== "boolean") ||
    (payload.type === "InvoiceReceivedPayment" &&
      typeof payload.afterExpiration !== "boolean") ||
    (payload.type === "InvoiceSettled" &&
      (typeof payload.manuallyMarked !== "boolean" ||
        typeof payload.overPaid !== "boolean"))
  ) {
    console.error("BTCPay webhook is missing required payment details.", {
      type: payload.type,
      invoiceId: payload.invoiceId,
    });
    return jsonResponse({ error: "Webhook is missing payment details." }, 400);
  }

  const metadata = isRecord(payload.metadata) ? payload.metadata : {};
  const orderId = typeof metadata.orderId === "string"
    ? metadata.orderId
    : null;
  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data: result, error } = await adminClient.rpc(
    "apply_btcpay_webhook_event",
    {
      p_invoice_id: payload.invoiceId,
      p_order_id: orderId,
      p_event_type: payload.type,
      p_partially_paid: payload.partiallyPaid === true,
      p_after_expiration: payload.afterExpiration === true,
      p_manually_marked: payload.manuallyMarked === true,
      p_overpaid: payload.overPaid === true,
    },
  );
  if (error) {
    console.error("Could not apply the BTCPay webhook to its order.", error);
    return jsonResponse({ error: "Could not update payment status." }, 500);
  }
  if (result === "unmatched" || result === "invoice_mismatch") {
    console.error("BTCPay webhook did not match a valid Souq order.", {
      result,
      invoiceId: payload.invoiceId,
    });
    return jsonResponse({ error: "Webhook does not match a Souq order." }, 500);
  }
  return jsonResponse({ ok: true, result });
});

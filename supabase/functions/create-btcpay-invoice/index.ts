import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const listingIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function requiredEnvironment(name: string) {
  return Deno.env.get(name)?.trim() || null;
}

function parseHttpsUrl(value: string) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" || url.username || url.password || url.search ||
      url.hash
    ) return null;
    return url;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed." }, 405);
  }

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) {
    return jsonResponse(
      { error: "Sign in before starting Bitcoin checkout." },
      401,
    );
  }

  const supabaseUrl = requiredEnvironment("SUPABASE_URL");
  const anonKey = requiredEnvironment("SUPABASE_ANON_KEY") ||
    requiredEnvironment("SUPABASE_PUBLISHABLE_KEY");
  const serviceRoleKey = requiredEnvironment("SUPABASE_SERVICE_ROLE_KEY");
  const btcpayServerValue = requiredEnvironment("BTCPAY_SERVER_URL");
  const storeId = requiredEnvironment("BTCPAY_STORE_ID");
  const apiKey = requiredEnvironment("BTCPAY_API_KEY");
  const webhookSecret = requiredEnvironment("BTCPAY_WEBHOOK_SECRET");
  const siteUrlValue = requiredEnvironment("SITE_URL");
  if (
    !supabaseUrl || !anonKey || !serviceRoleKey || !btcpayServerValue ||
    !storeId || !apiKey || !webhookSecret || !siteUrlValue
  ) {
    console.error(
      "Bitcoin checkout is missing one or more required server-side settings.",
    );
    return jsonResponse({
      error: "Bitcoin checkout is not configured yet. Please try again later.",
    }, 503);
  }

  const btcpayServerUrl = parseHttpsUrl(btcpayServerValue);
  const siteUrl = parseHttpsUrl(siteUrlValue);
  if (
    !btcpayServerUrl || !siteUrl || btcpayServerUrl.pathname !== "/" ||
    btcpayServerUrl.search || btcpayServerUrl.hash
  ) {
    console.error(
      "Bitcoin checkout requires valid HTTPS server and site URLs.",
    );
    return jsonResponse({
      error: "Bitcoin checkout is not configured correctly.",
    }, 503);
  }

  let requestBody: unknown;
  try {
    requestBody = await request.json();
  } catch {
    return jsonResponse({ error: "Request body must be valid JSON." }, 400);
  }
  if (
    !isRecord(requestBody) || typeof requestBody.listingId !== "string" ||
    !listingIdPattern.test(requestBody.listingId)
  ) {
    return jsonResponse({ error: "A valid listing ID is required." }, 400);
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: authorization } },
  });
  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) {
    return jsonResponse({
      error: "Your sign-in session is invalid. Sign in again to continue.",
    }, 401);
  }

  const { data: mfaAllowed, error: mfaError } = await userClient.rpc(
    "user_meets_mfa_requirement",
  );
  if (mfaError) {
    console.error(
      "Could not verify the buyer's authenticator status.",
      mfaError,
    );
    return jsonResponse({
      error:
        "Souq could not verify your authenticator status. Please try again.",
    }, 500);
  }
  if (mfaAllowed !== true) {
    return jsonResponse({
      error: "Complete authenticator verification before paying with Bitcoin.",
    }, 403);
  }

  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const markOrderFailed = async (orderId: string) => {
    const { error } = await adminClient
      .from("orders")
      .update({ status: "cancelled", payment_status: "failed" })
      .eq("id", orderId)
      .eq("payment_status", "creating");
    if (error) {
      console.error("Could not release a failed Bitcoin order", orderId, error);
    }
  };
  const markOrderForReview = async (orderId: string) => {
    const { error } = await adminClient
      .from("orders")
      .update({ payment_status: "needs_review" })
      .eq("id", orderId)
      .eq("payment_status", "creating");
    if (error) {
      console.error(
        "Could not flag an uncertain Bitcoin order for review",
        orderId,
        error,
      );
    }
  };
  const { data: createdOrders, error: orderError } = await adminClient.rpc(
    "create_btcpay_order",
    {
      p_listing_id: requestBody.listingId,
      p_buyer_id: userData.user.id,
    },
  );
  if (orderError) {
    if (orderError.code === "P0002") {
      return jsonResponse({ error: "This item is no longer available." }, 409);
    }
    if (orderError.code === "42501") {
      return jsonResponse({ error: "You can't buy your own listing." }, 403);
    }
    if (orderError.code === "23505") {
      const { data: existingOrder, error: existingOrderError } =
        await adminClient
          .from("orders")
          .select("id,payment_method,payment_status,payment_checkout_url")
          .eq("listing_id", requestBody.listingId)
          .eq("buyer_id", userData.user.id)
          .eq("status", "pending")
          .maybeSingle();
      if (existingOrderError) {
        console.error(
          "Could not check for an existing Bitcoin order.",
          existingOrderError,
        );
        return jsonResponse({
          error: "Souq could not check this purchase. Please try again.",
        }, 500);
      }
      if (
        existingOrder?.payment_method === "bitcoin" &&
        ["awaiting_payment", "processing"].includes(
          existingOrder.payment_status,
        ) &&
        typeof existingOrder.payment_checkout_url === "string"
      ) {
        return jsonResponse({
          orderId: existingOrder.id,
          checkoutUrl: existingOrder.payment_checkout_url,
        });
      }
      return jsonResponse({
        error: "This listing already has an active purchase request.",
      }, 409);
    }
    console.error("Could not create a Bitcoin order.", orderError);
    return jsonResponse({
      error: "Souq could not reserve this item. Please try again.",
    }, 500);
  }

  const order = Array.isArray(createdOrders) ? createdOrders[0] : null;
  if (
    !isRecord(order) || typeof order.order_id !== "string" ||
    typeof order.amount !== "number" && typeof order.amount !== "string"
  ) {
    console.error("Bitcoin order creation returned an invalid result.");
    return jsonResponse({
      error: "Souq could not prepare this purchase. Please try again.",
    }, 500);
  }

  const amount = Number(order.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    console.error(
      "The listing has an invalid Bitcoin checkout amount.",
      order.order_id,
    );
    await markOrderFailed(order.order_id);
    return jsonResponse({
      error: "This listing has an invalid price and cannot be purchased.",
    }, 500);
  }

  let invoiceResponse: Response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    invoiceResponse = await fetch(
      new URL(
        `/api/v1/stores/${encodeURIComponent(storeId)}/invoices`,
        btcpayServerUrl,
      ),
      {
        method: "POST",
        headers: {
          "Authorization": `token ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          amount: amount.toFixed(2),
          currency: "USD",
          metadata: {
            orderId: order.order_id,
            listingTitle: typeof order.listing_title === "string"
              ? order.listing_title
              : "Souq purchase",
          },
          checkout: {
            paymentMethods: ["BTC"],
            defaultPaymentMethod: "BTC",
            expirationMinutes: 30,
            redirectURL: siteUrl.href,
            redirectAutomatically: false,
          },
        }),
        redirect: "error",
        signal: controller.signal,
      },
    );
  } catch (error) {
    await markOrderForReview(order.order_id);
    console.error(
      "Could not confirm whether BTCPay created the invoice.",
      error,
    );
    return jsonResponse({
      error:
        "Bitcoin invoice creation could not be confirmed. This purchase needs review before retrying.",
    }, 502);
  } finally {
    clearTimeout(timeout);
  }

  let responseText: string;
  try {
    responseText = await invoiceResponse.text();
  } catch (error) {
    await markOrderForReview(order.order_id);
    console.error("Could not read the BTCPay invoice response.", error);
    return jsonResponse({
      error:
        "BTCPay's response could not be confirmed. This purchase needs review before retrying.",
    }, 502);
  }

  if (!invoiceResponse.ok) {
    console.error("BTCPay rejected invoice creation.", {
      status: invoiceResponse.status,
    });
    if (invoiceResponse.status >= 500) await markOrderForReview(order.order_id);
    else await markOrderFailed(order.order_id);
    return jsonResponse({
      error: invoiceResponse.status >= 500
        ? "BTCPay could not confirm invoice creation. This purchase needs review before retrying."
        : "BTCPay could not create the invoice. Please try again.",
    }, 502);
  }

  let invoicePayload: unknown;
  try {
    invoicePayload = JSON.parse(responseText);
  } catch {
    await markOrderForReview(order.order_id);
    console.error("BTCPay returned an invalid invoice response.");
    return jsonResponse({
      error:
        "BTCPay returned an invalid invoice response. This purchase needs review before retrying.",
    }, 502);
  }
  if (
    !isRecord(invoicePayload) ||
    typeof invoicePayload.id !== "string" ||
    typeof invoicePayload.checkoutLink !== "string"
  ) {
    await markOrderForReview(order.order_id);
    console.error(
      "BTCPay's invoice response is missing its ID or checkout link.",
    );
    return jsonResponse({
      error:
        "BTCPay returned incomplete invoice details. This purchase needs review before retrying.",
    }, 502);
  }

  let checkoutUrl: URL;
  try {
    checkoutUrl = new URL(invoicePayload.checkoutLink);
  } catch {
    await markOrderForReview(order.order_id);
    console.error("BTCPay returned an invalid checkout URL.");
    return jsonResponse({
      error:
        "BTCPay returned an invalid checkout link. This purchase needs review.",
    }, 502);
  }
  if (
    checkoutUrl.protocol !== "https:" ||
    checkoutUrl.origin !== btcpayServerUrl.origin
  ) {
    await markOrderForReview(order.order_id);
    console.error(
      "BTCPay returned a checkout URL outside the configured HTTPS server.",
    );
    return jsonResponse({
      error:
        "BTCPay returned an unsafe checkout link. This purchase needs review.",
    }, 502);
  }

  const expirationTimestamp = Number(invoicePayload.expirationTime);
  const paymentExpiresAt =
    Number.isFinite(expirationTimestamp) && expirationTimestamp > 0
      ? new Date(expirationTimestamp * 1000).toISOString()
      : new Date(Date.now() + 30 * 60 * 1000).toISOString();
  const { data: savedOrder, error: saveError } = await adminClient
    .from("orders")
    .update({
      payment_invoice_id: invoicePayload.id,
      payment_checkout_url: checkoutUrl.href,
      payment_expires_at: paymentExpiresAt,
      payment_status: "awaiting_payment",
    })
    .eq("id", order.order_id)
    .eq("payment_status", "creating")
    .select("id")
    .maybeSingle();
  if (saveError || !savedOrder) {
    console.error(
      "BTCPay created an invoice, but Souq could not save its reference.",
      saveError,
    );
    const { data: reconciledOrder, error: reconcileError } = await adminClient
      .from("orders")
      .select("id,payment_invoice_id,payment_checkout_url")
      .eq("id", order.order_id)
      .maybeSingle();
    if (reconcileError) {
      console.error(
        "Could not check whether the webhook already reconciled the invoice.",
        reconcileError,
      );
    }
    if (
      reconciledOrder?.payment_invoice_id === invoicePayload.id &&
      typeof reconciledOrder.payment_checkout_url === "string"
    ) {
      return jsonResponse({
        orderId: order.order_id,
        checkoutUrl: reconciledOrder.payment_checkout_url,
      });
    }
    return jsonResponse({
      error:
        "BTCPay created an invoice, but Souq could not save it. Do not retry this purchase; contact the Souq administrator.",
    }, 503);
  }

  return jsonResponse({
    orderId: order.order_id,
    checkoutUrl: checkoutUrl.href,
  });
});

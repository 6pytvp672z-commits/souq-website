type WebhookHandler = (request: Request) => Promise<Response>;

function assertEqual(actual: unknown, expected: unknown, message: string) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `${message}: expected ${JSON.stringify(expected)}, got ${
        JSON.stringify(actual)
      }`,
    );
  }
}

Deno.test("BTCPay webhook validates signatures and payment flags", async (t) => {
  const calls: unknown[] = [];
  const mockSupabase = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen: () => {} },
    async (request) => {
      if (
        new URL(request.url).pathname !==
          "/rest/v1/rpc/apply_btcpay_webhook_event"
      ) {
        return new Response("Not found", { status: 404 });
      }
      calls.push(await request.json());
      return Response.json("updated");
    },
  );
  const secret = "test-webhook-secret";
  const values = {
    SUPABASE_URL: `http://127.0.0.1:${mockSupabase.addr.port}`,
    SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
    BTCPAY_STORE_ID: "test-store",
    BTCPAY_WEBHOOK_SECRET: secret,
  };
  const previous = new Map(
    Object.keys(values).map((name) => [name, Deno.env.get(name)]),
  );
  const originalServe = Object.getOwnPropertyDescriptor(Deno, "serve");

  try {
    for (const [name, value] of Object.entries(values)) {
      Deno.env.set(name, value);
    }

    const captured: { handler?: WebhookHandler } = {};
    Object.defineProperty(Deno, "serve", {
      configurable: true,
      value: (handler: WebhookHandler) => {
        captured.handler = handler;
      },
    });
    try {
      await import("./index.ts");
    } finally {
      if (originalServe) Object.defineProperty(Deno, "serve", originalServe);
    }
    if (!captured.handler) {
      throw new Error("Webhook handler was not registered");
    }
    const handler = captured.handler;

    const signedRequest = async (
      event: Record<string, unknown>,
      validSignature = true,
    ) => {
      const body = JSON.stringify({
        storeId: "test-store",
        invoiceId: "test-invoice",
        metadata: { orderId: "test-order" },
        ...event,
      });
      const secretBytes = new TextEncoder().encode(secret);
      const secretBuffer = new ArrayBuffer(secretBytes.byteLength);
      new Uint8Array(secretBuffer).set(secretBytes);
      const bodyBytes = new TextEncoder().encode(body);
      const bodyBuffer = new ArrayBuffer(bodyBytes.byteLength);
      new Uint8Array(bodyBuffer).set(bodyBytes);
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
      const signature = Array.from(
        digest,
        (byte) => byte.toString(16).padStart(2, "0"),
      ).join("");
      return handler(
        new Request("http://localhost/btcpay-webhook", {
          method: "POST",
          headers: {
            "BTCPay-Sig": `sha256=${
              validSignature ? signature : "0".repeat(64)
            }`,
          },
          body,
        }),
      );
    };

    const cases = [
      {
        name: "forwards late payments",
        event: { type: "InvoiceReceivedPayment", afterExpiration: true },
        flags: [false, true, false, false],
      },
      {
        name: "forwards partial expirations",
        event: { type: "InvoiceExpired", partiallyPaid: true },
        flags: [true, false, false, false],
      },
      {
        name: "forwards manually marked settlements",
        event: {
          type: "InvoiceSettled",
          manuallyMarked: true,
          overPaid: false,
        },
        flags: [false, false, true, false],
      },
      {
        name: "forwards overpayments",
        event: {
          type: "InvoiceSettled",
          manuallyMarked: false,
          overPaid: true,
        },
        flags: [false, false, false, true],
      },
      {
        name: "forwards ordinary settlements",
        event: {
          type: "InvoiceSettled",
          manuallyMarked: false,
          overPaid: false,
        },
        flags: [false, false, false, false],
      },
    ];
    for (const testCase of cases) {
      await t.step(testCase.name, async () => {
        const before = calls.length;
        const response = await signedRequest(testCase.event);
        assertEqual(response.status, 200, "response status");
        assertEqual(calls.length, before + 1, "RPC count");
        assertEqual(calls.at(-1), {
          p_invoice_id: "test-invoice",
          p_order_id: "test-order",
          p_event_type: testCase.event.type,
          p_partially_paid: testCase.flags[0],
          p_after_expiration: testCase.flags[1],
          p_manually_marked: testCase.flags[2],
          p_overpaid: testCase.flags[3],
        }, "RPC arguments");
      });
    }

    await t.step("rejects an invalid signature", async () => {
      const before = calls.length;
      const response = await signedRequest({
        type: "InvoiceReceivedPayment",
        afterExpiration: true,
      }, false);
      assertEqual(response.status, 401, "response status");
      assertEqual(calls.length, before, "RPC count");
    });
    await t.step("rejects missing payment flags", async () => {
      const before = calls.length;
      const response = await signedRequest({ type: "InvoiceSettled" });
      assertEqual(response.status, 400, "response status");
      assertEqual(calls.length, before, "RPC count");
    });
    await t.step("rejects another store", async () => {
      const before = calls.length;
      const response = await signedRequest({
        storeId: "other-store",
        type: "InvoiceReceivedPayment",
        afterExpiration: false,
      });
      assertEqual(response.status, 400, "response status");
      assertEqual(calls.length, before, "RPC count");
    });
  } finally {
    if (originalServe) Object.defineProperty(Deno, "serve", originalServe);
    for (const [name, value] of previous) {
      if (value === undefined) Deno.env.delete(name);
      else Deno.env.set(name, value);
    }
    await mockSupabase.shutdown();
  }
});

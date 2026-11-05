# BTCPay Server checkout

Souq's Bitcoin checkout creates USD-priced BTCPay invoices that accept BTC only. Payments go to the configured Souq BTCPay Store; Souq must pay sellers separately. The seller payout state is visible in My orders, but sending seller payouts is a manual operation and is not performed by this integration.

Bitcoin checkout is disabled by default. Live listings show "Bitcoin checkout coming soon" until the database, functions, store, and webhook are configured and tested.

## Configure

1. Set up an HTTPS BTCPay Server and a Souq Store with its Bitcoin wallet/payment method configured. Create an API key restricted to `btcpay.store.cancreateinvoice`.
2. Apply the database migration and deploy the functions:

   ```sh
   supabase db push
   supabase functions deploy create-btcpay-invoice
   supabase functions deploy btcpay-webhook
   ```

3. After the migration has been applied, set `BITCOIN_ORDER_FIELDS_AVAILABLE` to `true` in `index.html` so existing Bitcoin orders can be displayed. Keep this setting enabled if new checkout is later paused.

4. In the BTCPay Store, add a webhook for `InvoiceSettled`, `InvoiceExpired`, `InvoiceInvalid`, `InvoiceProcessing`, and `InvoiceReceivedPayment`. Keep automatic redelivery enabled. Use this endpoint:

   ```text
   https://fwfqeajhtxzubxuywfrm.supabase.co/functions/v1/btcpay-webhook
   ```

5. Store the BTCPay values as Supabase Edge Function secrets; never put them in `index.html` or share them in chat:

   ```sh
   supabase secrets set \
     BTCPAY_SERVER_URL=https://btcpay.example.org \
     BTCPAY_STORE_ID=your-store-id \
     BTCPAY_API_KEY=your-invoice-only-api-key \
     BTCPAY_WEBHOOK_SECRET=the-secret-configured-on-the-webhook \
     SITE_URL=https://your-souq-site.example
   ```

   Supabase supplies `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` to Edge Functions. The invoice function also accepts `SUPABASE_PUBLISHABLE_KEY` when the anon key is unavailable. Do not expose the service-role key.

6. In a private test deployment, set `BITCOIN_CHECKOUT_REQUESTED` to `true` and test invoice creation, payment processing, a settled invoice, an expired invoice, late and partial payments, duplicate webhook deliveries, and an invalid-signature webhook. Only enable that setting on the public site after testing succeeds. Both settings must be `true` for checkout to be enabled.

   The invoice amount is recorded when the order is created. Only an automatically settled, non-overpaid invoice is treated as paid; manually marked settlements, overpayments, late or partial payments, and invalid invoices require a refund or manual review. Duplicate settlements must not reset a seller payout already marked paid.

## Regression tests

Run the signed-webhook tests with Deno:

```sh
deno test --allow-env --allow-net --allow-read supabase/functions/btcpay-webhook/index_test.ts
```

After applying the migration to an isolated test database, run the SQL transition tests using a `psql` connection to that database:

```sh
psql -v ON_ERROR_STOP=1 -f supabase/test-scripts/btcpay_payment_transitions.sql
```

## Seller payouts

After paying a seller outside Souq, record it in the Supabase SQL Editor:

```sql
update public.orders
set payout_status = 'paid',
    payout_paid_at = now()
where id = 'ORDER_UUID'
  and payment_method = 'bitcoin'
  and payment_status = 'paid'
  and payout_status = 'pending';
```

Only mark the payout paid after verifying the transfer. Orders marked `refund_due` or `needs_review` require administrator review in BTCPay before being resolved.

-- Run against an isolated database after applying the BTCPay migration.
begin;

create temporary table listings (
  id uuid primary key,
  seller_id uuid not null,
  title text not null,
  price numeric(12, 2) not null,
  status text not null
) on commit drop;

create temporary table orders (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid,
  buyer_id uuid,
  seller_id uuid,
  status text not null default 'pending',
  payment_method text not null default 'manual',
  payment_status text not null default 'not_required',
  payment_amount_usd numeric(12, 2),
  payment_invoice_id text,
  payout_status text not null default 'not_applicable',
  paid_at timestamptz
) on commit drop;

do $clone$
declare
  definition text;
begin
  definition := pg_get_functiondef(
    'public.create_btcpay_order(uuid,uuid)'::regprocedure
  );
  definition := replace(definition, 'public.create_btcpay_order', 'pg_temp.create_btcpay_order');
  definition := replace(definition, 'public.listings', 'pg_temp.listings');
  definition := replace(definition, 'public.orders', 'pg_temp.orders');
  execute definition;

  definition := pg_get_functiondef(
    'public.apply_btcpay_webhook_event(text,text,text,boolean,boolean,boolean,boolean)'::regprocedure
  );
  definition := replace(definition, 'public.apply_btcpay_webhook_event', 'pg_temp.apply_btcpay_webhook_event');
  definition := replace(definition, 'public.orders', 'pg_temp.orders');
  execute definition;
end;
$clone$;

create function pg_temp.assert_order(
  p_id uuid,
  p_payment_status text,
  p_order_status text,
  p_payout_status text
)
returns void
language plpgsql
as $$
begin
  if not exists (
    select 1 from pg_temp.orders
    where id = p_id
      and payment_status = p_payment_status
      and status = p_order_status
      and payout_status = p_payout_status
  ) then
    raise exception 'Unexpected payment, order, or payout state for %', p_id;
  end if;
end;
$$;

do $test$
declare
  order_id uuid;
  invoice_amount numeric;
begin
  insert into pg_temp.listings (id, seller_id, title, price, status)
  values (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    'Test listing',
    12.34,
    'available'
  );
  select created.order_id, created.amount into order_id, invoice_amount
  from pg_temp.create_btcpay_order(
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000003'
  ) as created;
  update pg_temp.listings set price = 99.00;
  if invoice_amount <> 12.34 or not exists (
    select 1 from pg_temp.orders as orders
    where orders.id = order_id and orders.payment_amount_usd = 12.34
  ) then
    raise exception 'Bitcoin order did not retain its original amount';
  end if;

  update pg_temp.orders set payment_invoice_id = 'invoice-1', payment_status = 'processing';
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceSettled', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'paid', 'pending', 'pending');
  update pg_temp.orders set payout_status = 'paid' where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceSettled', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'paid', 'pending', 'paid');

  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceInvalid', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'needs_review', 'pending', 'paid');
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceSettled', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'needs_review', 'pending', 'paid');

  update pg_temp.orders
  set status = 'pending', payment_status = 'awaiting_payment', payout_status = 'not_applicable', paid_at = null
  where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceExpired', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'expired', 'cancelled', 'not_applicable');
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceReceivedPayment', false, true, false, false);
  perform pg_temp.assert_order(order_id, 'refund_due', 'cancelled', 'not_applicable');

  update pg_temp.orders
  set status = 'pending', payment_status = 'awaiting_payment', payout_status = 'not_applicable'
  where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceReceivedPayment', false, true, false, false);
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceExpired', false, false, false, false);
  perform pg_temp.assert_order(order_id, 'refund_due', 'cancelled', 'not_applicable');

  update pg_temp.orders
  set status = 'pending', payment_status = 'awaiting_payment', payout_status = 'not_applicable'
  where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceExpired', true, false, false, false);
  perform pg_temp.assert_order(order_id, 'refund_due', 'cancelled', 'not_applicable');

  update pg_temp.orders
  set status = 'pending', payment_status = 'processing', payout_status = 'not_applicable', paid_at = null
  where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceSettled', false, false, true, false);
  perform pg_temp.assert_order(order_id, 'needs_review', 'pending', 'not_applicable');
  if exists (select 1 from pg_temp.orders where id = order_id and paid_at is not null) then
    raise exception 'A manually marked settlement was recorded as confirmed payment';
  end if;

  update pg_temp.orders set payment_status = 'processing' where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceSettled', false, false, false, true);
  perform pg_temp.assert_order(order_id, 'needs_review', 'pending', 'not_applicable');

  update pg_temp.orders set status = 'cancelled', payment_status = 'refunded' where id = order_id;
  perform pg_temp.apply_btcpay_webhook_event('invoice-1', null, 'InvoiceReceivedPayment', false, true, false, false);
  perform pg_temp.assert_order(order_id, 'needs_review', 'cancelled', 'not_applicable');
end;
$test$;

select 'BTCPay payment transition tests passed' as result;
rollback;

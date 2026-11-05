alter table public.orders
  add column if not exists payment_method text not null default 'manual',
  add column if not exists payment_status text not null default 'not_required',
  add column if not exists payment_invoice_id text,
  add column if not exists payment_checkout_url text,
  add column if not exists payment_expires_at timestamptz,
  add column if not exists payment_amount_usd numeric(12, 2),
  add column if not exists paid_at timestamptz,
  add column if not exists payout_status text not null default 'not_applicable',
  add column if not exists payout_paid_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'orders_payment_method_check'
      and conrelid = 'public.orders'::regclass
  ) then
    alter table public.orders
      add constraint orders_payment_method_check
      check (payment_method in ('manual', 'bitcoin'));
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'orders_payment_status_check'
      and conrelid = 'public.orders'::regclass
  ) then
    alter table public.orders
      add constraint orders_payment_status_check
      check (payment_status in (
        'not_required', 'creating', 'awaiting_payment', 'processing', 'paid',
        'expired', 'failed', 'needs_review', 'refund_due', 'refunded'
      ));
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'orders_payment_amount_usd_check'
      and conrelid = 'public.orders'::regclass
  ) then
    alter table public.orders
      add constraint orders_payment_amount_usd_check
      check (payment_amount_usd is null or payment_amount_usd > 0);
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'orders_payout_status_check'
      and conrelid = 'public.orders'::regclass
  ) then
    alter table public.orders
      add constraint orders_payout_status_check
      check (payout_status in ('not_applicable', 'pending', 'paid'));
  end if;
end;
$$;

create unique index if not exists orders_payment_invoice_id_unique
  on public.orders (payment_invoice_id)
  where payment_invoice_id is not null;

drop policy if exists "Sellers can complete pending orders" on public.orders;
create policy "Sellers can complete pending orders"
  on public.orders for update to authenticated
  using (
    (select public.user_meets_mfa_requirement())
    and seller_id = (select auth.uid())
    and status = 'pending'
  )
  with check (
    (select public.user_meets_mfa_requirement())
    and seller_id = (select auth.uid())
    and (
      (
        status = 'completed'
        and (payment_method = 'manual' or payment_status = 'paid')
      )
      or (
        status = 'cancelled'
        and (payment_method = 'manual' or payment_status in ('expired', 'failed'))
      )
    )
  );

create or replace function public.create_btcpay_order(
  p_listing_id uuid,
  p_buyer_id uuid
)
returns table(order_id uuid, seller_id uuid, listing_title text, amount numeric)
language plpgsql
security definer
set search_path = ''
as $$
declare
  listing_row public.listings%rowtype;
begin
  select *
  into listing_row
  from public.listings
  where id = p_listing_id and status = 'available'
  for update;

  if not found then
    raise exception using errcode = 'P0002', message = 'Listing is not available';
  end if;

  if listing_row.seller_id = p_buyer_id then
    raise exception using errcode = '42501', message = 'Cannot buy your own listing';
  end if;

  insert into public.orders (
    listing_id,
    buyer_id,
    seller_id,
    payment_method,
    payment_status,
    payment_amount_usd
  )
  values (
    p_listing_id,
    p_buyer_id,
    listing_row.seller_id,
    'bitcoin',
    'creating',
    listing_row.price
  )
  returning id into order_id;

  seller_id := listing_row.seller_id;
  listing_title := listing_row.title;
  amount := listing_row.price;
  return next;
end;
$$;

revoke all on function public.create_btcpay_order(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.create_btcpay_order(uuid, uuid)
  to service_role;

drop function if exists public.apply_btcpay_webhook_event(text, text, text, boolean);

create or replace function public.apply_btcpay_webhook_event(
  p_invoice_id text,
  p_order_id text,
  p_event_type text,
  p_partially_paid boolean default false,
  p_after_expiration boolean default false,
  p_manually_marked boolean default false,
  p_overpaid boolean default false
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  order_row public.orders%rowtype;
begin
  if p_invoice_id is null or btrim(p_invoice_id) = '' then
    raise exception 'Invoice ID is required';
  end if;

  if p_event_type not in (
    'InvoiceSettled', 'InvoiceExpired', 'InvoiceInvalid',
    'InvoiceProcessing', 'InvoiceReceivedPayment'
  ) then
    return 'ignored';
  end if;

  select *
  into order_row
  from public.orders
  where payment_method = 'bitcoin'
    and (
      payment_invoice_id = p_invoice_id
      or (payment_invoice_id is null and id::text = p_order_id)
    )
  for update;

  if not found then
    return 'unmatched';
  end if;

  if order_row.payment_invoice_id is not null
    and order_row.payment_invoice_id <> p_invoice_id then
    return 'invoice_mismatch';
  end if;

  if p_event_type = 'InvoiceReceivedPayment' and p_after_expiration then
    update public.orders
    set payment_invoice_id = p_invoice_id,
        payment_status = case
          when order_row.payment_status in ('paid', 'refunded')
            or order_row.status = 'completed' then 'needs_review'
          else 'refund_due'
        end,
        payout_status = case
          when order_row.payout_status = 'paid' then 'paid'
          else 'not_applicable'
        end,
        status = case
          when order_row.status = 'pending'
            and order_row.payment_status not in ('paid', 'refunded')
            then 'cancelled'
          else order_row.status
        end
    where id = order_row.id;
    return 'updated';
  end if;

  if order_row.payment_status = 'refunded' then
    return 'unchanged';
  end if;

  if p_event_type = 'InvoiceSettled' then
    update public.orders
    set payment_invoice_id = p_invoice_id,
        payment_status = case
          when order_row.payment_status = 'refund_due' then 'refund_due'
          when p_manually_marked then 'needs_review'
          when order_row.status = 'cancelled'
            or order_row.payment_status = 'expired'
            then 'refund_due'
          when p_overpaid or order_row.payment_status = 'needs_review'
            then 'needs_review'
          else 'paid'
        end,
        payout_status = case
          when order_row.payout_status = 'paid' then 'paid'
          when order_row.status = 'cancelled'
            or order_row.payment_status in ('expired', 'refund_due', 'needs_review')
            or p_manually_marked or p_overpaid
            then 'not_applicable'
          else 'pending'
        end,
        paid_at = case
          when p_manually_marked then paid_at
          else coalesce(paid_at, now())
        end
    where id = order_row.id;
  elsif p_event_type = 'InvoiceExpired' then
    if order_row.payment_status in ('paid', 'refund_due', 'needs_review') then
      return 'unchanged';
    end if;

    update public.orders
    set payment_invoice_id = p_invoice_id,
        payment_status = case when p_partially_paid then 'refund_due' else 'expired' end,
        payout_status = 'not_applicable',
        status = case when status = 'pending' then 'cancelled' else status end
    where id = order_row.id;
  elsif p_event_type = 'InvoiceInvalid' then
    if order_row.payment_status = 'refund_due' then
      return 'unchanged';
    end if;

    update public.orders
    set payment_invoice_id = p_invoice_id,
        payment_status = 'needs_review',
        payout_status = case
          when order_row.payout_status = 'paid' then 'paid'
          else 'not_applicable'
        end
    where id = order_row.id;
  else
    if order_row.payment_status not in ('creating', 'awaiting_payment', 'processing') then
      return 'unchanged';
    end if;

    update public.orders
    set payment_invoice_id = p_invoice_id,
        payment_status = 'processing'
    where id = order_row.id;
  end if;

  return 'updated';
end;
$$;

revoke all on function public.apply_btcpay_webhook_event(text, text, text, boolean, boolean, boolean, boolean)
  from public, anon, authenticated;
grant execute on function public.apply_btcpay_webhook_event(text, text, text, boolean, boolean, boolean, boolean)
  to service_role;

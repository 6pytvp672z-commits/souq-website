create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null
    check (char_length(btrim(display_name)) between 1 and 80),
  username text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles
  add column if not exists username text;

update public.profiles
set username = 'member_' || left(replace(id::text, '-', ''), 12)
where username is null or btrim(username) = '';

alter table public.profiles
  alter column username set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'profiles_username_format'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_username_format
      check (username ~ '^[A-Za-z0-9_]{3,24}$');
  end if;
end;
$$;

create unique index if not exists profiles_username_ci_unique
  on public.profiles (lower(username));

alter table public.profiles enable row level security;

revoke all on public.profiles from anon, authenticated;
grant select, update on public.profiles to authenticated;

create or replace function public.user_meets_mfa_requirement()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    not exists (
      select 1
      from auth.mfa_factors
      where user_id = (select auth.uid())
        and status = 'verified'
    )
    or coalesce((select auth.jwt() ->> 'aal'), '') = 'aal2';
$$;

revoke all on function public.user_meets_mfa_requirement() from public;
grant execute on function public.user_meets_mfa_requirement() to anon, authenticated;

drop policy if exists "Users can read their own profile" on public.profiles;
create policy "Users can read their own profile"
  on public.profiles
  for select
  to authenticated
  using ((select public.user_meets_mfa_requirement()) and (select auth.uid()) = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles
  for update
  to authenticated
  using ((select public.user_meets_mfa_requirement()) and (select auth.uid()) = id)
  with check ((select public.user_meets_mfa_requirement()) and (select auth.uid()) = id);

create or replace function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name, username)
  values (
    new.id,
    coalesce(
      nullif(left(btrim(new.raw_user_meta_data ->> 'display_name'), 80), ''),
      'Souq member'
    ),
    case
      when coalesce(new.raw_user_meta_data ->> 'username', '') ~ '^[A-Za-z0-9_]{3,24}$'
        then new.raw_user_meta_data ->> 'username'
      else 'member_' || left(replace(new.id::text, '-', ''), 12)
    end
  )
  on conflict (id) do update
  set display_name = excluded.display_name;
  return new;
end;
$$;

revoke execute on function public.create_profile_for_new_user() from public, anon, authenticated;

drop trigger if exists create_profile_after_signup on auth.users;
create trigger create_profile_after_signup
  after insert on auth.users
  for each row execute function public.create_profile_for_new_user();

create or replace function public.lookup_user_login(lookup_username text)
returns table(email text, phone text)
language sql
security definer
set search_path = ''
as $$
  select users.email, users.phone
  from auth.users as users
  join public.profiles as profiles on profiles.id = users.id
  where lower(profiles.username) = lower(btrim(lookup_username))
  limit 1;
$$;

revoke all on function public.lookup_user_login(text) from public, anon, authenticated;
grant execute on function public.lookup_user_login(text) to service_role;

create or replace view public.seller_public_profiles
with (security_invoker = false)
as
  select id, username
  from public.profiles;

grant select on public.seller_public_profiles to anon, authenticated;

create table if not exists public.listings (
  id uuid primary key default gen_random_uuid(),
  seller_id uuid not null references auth.users (id) on delete cascade,
  title text not null check (char_length(btrim(title)) between 1 and 100),
  category text not null check (char_length(btrim(category)) between 1 and 40),
  description text not null check (char_length(btrim(description)) between 10 and 2000),
  price numeric(12, 2) not null check (price > 0),
  location text not null check (char_length(btrim(location)) between 1 and 100),
  status text not null default 'available' check (status in ('available', 'sold')),
  created_at timestamptz not null default now()
);

create index if not exists listings_available_created_idx
  on public.listings (created_at desc)
  where status = 'available';
create index if not exists listings_seller_idx on public.listings (seller_id);

alter table public.listings enable row level security;
revoke all on public.listings from anon, authenticated;
grant select on public.listings to anon, authenticated;
grant insert, update on public.listings to authenticated;

drop policy if exists "Anyone can view available listings" on public.listings;
create policy "Anyone can view available listings"
  on public.listings for select to anon, authenticated
  using (
    status = 'available'
    or (
      (select public.user_meets_mfa_requirement())
      and (
        (select auth.uid()) = seller_id
        or (select auth.uid()) is not null
      )
    )
  );

drop policy if exists "Sellers can create listings" on public.listings;
create policy "Sellers can create listings"
  on public.listings for insert to authenticated
  with check (
    (select public.user_meets_mfa_requirement())
    and (select auth.uid()) = seller_id
    and status = 'available'
  );

drop policy if exists "Sellers can update their listings" on public.listings;
create policy "Sellers can update their listings"
  on public.listings for update to authenticated
  using ((select public.user_meets_mfa_requirement()) and (select auth.uid()) = seller_id)
  with check ((select public.user_meets_mfa_requirement()) and (select auth.uid()) = seller_id);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid not null references public.listings (id) on delete restrict,
  buyer_id uuid not null references auth.users (id) on delete cascade,
  seller_id uuid not null references auth.users (id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'completed', 'cancelled')),
  payment_method text not null default 'manual',
  payment_status text not null default 'not_required',
  payment_invoice_id text,
  payment_checkout_url text,
  payment_expires_at timestamptz,
  payment_amount_usd numeric(12, 2),
  paid_at timestamptz,
  payout_status text not null default 'not_applicable',
  payout_paid_at timestamptz,
  created_at timestamptz not null default now(),
  check (buyer_id <> seller_id),
  constraint orders_payment_method_check
    check (payment_method in ('manual', 'bitcoin')),
  constraint orders_payment_status_check
    check (payment_status in (
      'not_required', 'creating', 'awaiting_payment', 'processing', 'paid',
      'expired', 'failed', 'needs_review', 'refund_due', 'refunded'
    )),
  constraint orders_payment_amount_usd_check
    check (payment_amount_usd is null or payment_amount_usd > 0),
  constraint orders_payout_status_check
    check (payout_status in ('not_applicable', 'pending', 'paid'))
);

create unique index if not exists orders_one_active_purchase_per_listing
  on public.orders (listing_id)
  where status in ('pending', 'completed');
create unique index if not exists orders_payment_invoice_id_unique
  on public.orders (payment_invoice_id)
  where payment_invoice_id is not null;
create index if not exists orders_buyer_created_idx on public.orders (buyer_id, created_at desc);
create index if not exists orders_seller_created_idx on public.orders (seller_id, created_at desc);

create or replace function public.user_can_view_listing(target_listing_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.orders
    where orders.listing_id = target_listing_id
      and orders.buyer_id = (select auth.uid())
  );
$$;

revoke all on function public.user_can_view_listing(uuid) from public, anon;
grant execute on function public.user_can_view_listing(uuid) to anon, authenticated;

drop policy if exists "Anyone can view available listings" on public.listings;
create policy "Anyone can view available listings"
  on public.listings for select to anon, authenticated
  using (
    status = 'available'
    or (
      (select public.user_meets_mfa_requirement())
      and (
        (select auth.uid()) = seller_id
        or (select public.user_can_view_listing(id))
      )
    )
  );

alter table public.orders enable row level security;
revoke all on public.orders from public, anon, authenticated;
grant select on public.orders to authenticated;
grant insert (listing_id, buyer_id, seller_id) on public.orders to authenticated;
grant update (status) on public.orders to authenticated;

drop policy if exists "Buyers and sellers can view their orders" on public.orders;
create policy "Buyers and sellers can view their orders"
  on public.orders for select to authenticated
  using (
    (select public.user_meets_mfa_requirement())
    and (select auth.uid()) in (buyer_id, seller_id)
  );

drop policy if exists "Buyers can request available listings" on public.orders;
create policy "Buyers can request available listings"
  on public.orders for insert to authenticated
  with check (
    (select public.user_meets_mfa_requirement())
    and buyer_id = (select auth.uid())
    and status = 'pending'
    and exists (
      select 1
      from public.listings
      where listings.id = orders.listing_id
        and listings.seller_id = orders.seller_id
        and listings.status = 'available'
    )
  );

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

create or replace function public.mark_listing_sold_after_order_completion()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status = 'completed' and old.status is distinct from new.status then
    update public.listings
    set status = 'sold'
    where id = new.listing_id and seller_id = new.seller_id and status = 'available';
    if not found then
      raise exception 'This listing is no longer available';
    end if;
  end if;
  return new;
end;
$$;

revoke execute on function public.mark_listing_sold_after_order_completion() from public, anon, authenticated;
drop trigger if exists mark_listing_sold_after_order_completion on public.orders;
create trigger mark_listing_sold_after_order_completion
  before update of status on public.orders
  for each row execute function public.mark_listing_sold_after_order_completion();

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

create table if not exists public.seller_reviews (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null unique references public.orders (id) on delete cascade,
  buyer_id uuid not null references auth.users (id) on delete cascade,
  seller_id uuid not null references auth.users (id) on delete cascade,
  rating smallint not null check (rating between 1 and 5),
  comment text not null default '' check (char_length(comment) <= 500),
  created_at timestamptz not null default now()
);

create index if not exists seller_reviews_seller_idx on public.seller_reviews (seller_id);
alter table public.seller_reviews enable row level security;
revoke all on public.seller_reviews from anon, authenticated;
grant select on public.seller_reviews to anon, authenticated;
grant insert on public.seller_reviews to authenticated;

revoke select on public.seller_reviews from anon;
drop policy if exists "Anyone can read seller ratings" on public.seller_reviews;
drop policy if exists "Participants can read their seller reviews" on public.seller_reviews;
create policy "Participants can read their seller reviews"
  on public.seller_reviews for select to authenticated
  using (
    (select public.user_meets_mfa_requirement())
    and (select auth.uid()) in (buyer_id, seller_id)
  );

drop policy if exists "Buyers can rate completed sales" on public.seller_reviews;
create policy "Buyers can rate completed sales"
  on public.seller_reviews for insert to authenticated
  with check (
    (select public.user_meets_mfa_requirement())
    and buyer_id = (select auth.uid())
    and exists (
      select 1
      from public.orders
      where orders.id = seller_reviews.order_id
        and orders.buyer_id = (select auth.uid())
        and orders.seller_id = seller_reviews.seller_id
        and orders.status = 'completed'
    )
  );

create or replace view public.seller_rating_summary
with (security_invoker = false)
as
  select seller_id, round(avg(rating)::numeric, 1) as average_rating, count(*)::integer as rating_count
  from public.seller_reviews
  group by seller_id;

grant select on public.seller_rating_summary to anon, authenticated;

create table if not exists public.product_reviews (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid not null references public.listings (id) on delete cascade,
  order_id uuid not null unique references public.orders (id) on delete cascade,
  buyer_id uuid not null references auth.users (id) on delete cascade,
  rating smallint not null check (rating between 1 and 5),
  created_at timestamptz not null default now(),
  unique (listing_id, buyer_id)
);

alter table public.product_reviews enable row level security;
revoke all on public.product_reviews from public, anon, authenticated;
grant select, insert on public.product_reviews to authenticated;

drop policy if exists "Customers can view their product ratings" on public.product_reviews;
create policy "Customers can view their product ratings"
  on public.product_reviews for select to authenticated
  using (
    (select public.user_meets_mfa_requirement())
    and buyer_id = (select auth.uid())
  );

drop policy if exists "Customers can rate completed purchases" on public.product_reviews;
create policy "Customers can rate completed purchases"
  on public.product_reviews for insert to authenticated
  with check (
    (select public.user_meets_mfa_requirement())
    and buyer_id = (select auth.uid())
    and exists (
      select 1
      from public.orders
      where orders.id = product_reviews.order_id
        and orders.listing_id = product_reviews.listing_id
        and orders.buyer_id = (select auth.uid())
        and orders.status = 'completed'
    )
  );

create or replace view public.product_rating_summary
with (security_invoker = false)
as
  select
    listing_id,
    round(avg(rating)::numeric, 1) as average_rating,
    count(*)::integer as rating_count
  from public.product_reviews
  group by listing_id;

grant select on public.product_rating_summary to anon, authenticated;

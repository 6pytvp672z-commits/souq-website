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

drop policy if exists "Users can read their own profile" on public.profiles;
create policy "Users can read their own profile"
  on public.profiles
  for select
  to authenticated
  using ((select auth.uid()) = id);

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles
  for update
  to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

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

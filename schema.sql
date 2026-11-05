-- Paste this whole file into Supabase > SQL Editor > Run
create extension if not exists pgcrypto;

create table users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text unique not null,
  role text not null check (role in ('buyer','seller')),
  pass_hash text not null,
  created_at timestamptz default now()
);
create table dealers (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references users(id) on delete cascade,
  name text not null,
  location text,
  phone text,
  created_at timestamptz default now()
);
create table parts (
  id uuid primary key default gen_random_uuid(),
  dealer_id uuid not null references dealers(id) on delete cascade,
  name text not null,
  brand text,
  price numeric(10,2) not null check (price >= 0),
  stock int not null check (stock >= 0),
  img text,
  created_at timestamptz default now()
);
create table orders (
  id uuid primary key default gen_random_uuid(),
  dealer_id uuid not null references dealers(id),
  buyer_id uuid not null references users(id),
  buyer_name text,
  buyer_phone text,
  part_name text not null,
  qty int not null check (qty > 0),
  total numeric(10,2) not null,
  mode text not null check (mode in ('pickup','delivery')),
  address text default '',
  status int not null default 0,
  rider text default '',
  created_at timestamptz default now()
);
create index on parts (dealer_id);
create index on orders (dealer_id);
create index on orders (buyer_id);

-- Lock the tables: only the server (service key) can read or write them.
alter table users enable row level security;
alter table dealers enable row level security;
alter table parts enable row level security;
alter table orders enable row level security;

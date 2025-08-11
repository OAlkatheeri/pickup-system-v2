-- =========================================================
-- Pickup System: FULL SCHEMA (tables + RLS + RPCs/functions)
-- Safe to run in Supabase
-- =========================================================

-- extension
create extension if not exists pgcrypto;

-- ENUM types
DO $$BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'request_status') THEN
    CREATE TYPE request_status AS ENUM (
      'Pending','Assigning','Assigned',
      'En Route','Arrived','Started',
      'Completed','Rejected','Canceled'
    );
  END IF;
END$$;

DO $$BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_type') THEN
    CREATE TYPE alert_type AS ENUM ('OldRequestViewed','LongTrip','Custom');
  END IF;
END$$;

-- TABLES
create table if not exists employees (
  id bigserial primary key,
  employee_id text unique not null,
  full_name text not null,
  phone text,
  designation text,
  department text,
  is_active boolean default true,
  created_at timestamptz default now()
);

create table if not exists drivers (
  id bigserial primary key,
  employee_id text unique not null,
  full_name text not null,
  phone text not null,
  home_location jsonb,
  password_hash text not null,
  is_active boolean default true,
  created_at timestamptz default now()
);

create table if not exists cars (
  id bigserial primary key,
  color text,
  model text,
  type text check (type in ('Private','Public')),
  seaters int check (seaters > 0),
  plate_state text check (plate_state in ('Abu Dhabi','Dubai','Sharjah','Ajman','Umm Al Quwain','Ras Al Khaimah','Fujairah')),
  plate_type text check (plate_type in ('Private','Public')),
  plate_category text,
  plate_number int check (plate_number between 1 and 99999),
  location jsonb,
  is_active boolean default true,
  created_at timestamptz default now()
);

create table if not exists driver_car_assignments (
  id bigserial primary key,
  driver_id bigint references drivers(id) on delete cascade,
  car_id bigint references cars(id) on delete cascade,
  assignment_date date not null default current_date,
  created_at timestamptz default now(),
  unique (driver_id, assignment_date)
);

create table if not exists requests (
  id uuid primary key default gen_random_uuid(),
  employee_id text not null,
  full_name text not null,
  phone text not null,
  designation text,
  passengers int not null check (passengers > 0),
  purpose text,
  note text,
  pickup_location jsonb not null,
  dropoff_location jsonb not null,
  requested_at timestamptz not null,
  status request_status not null default 'Pending',
  status_updated_at timestamptz default now(),
  assigned_driver_id bigint references drivers(id),
  assigned_car_id bigint references cars(id),
  created_at timestamptz default now()
);

create index if not exists idx_requests_phone on requests(phone);
create index if not exists idx_requests_driver on requests(assigned_driver_id);
create index if not exists idx_requests_status on requests(status);

create table if not exists request_status_history (
  id bigserial primary key,
  request_id uuid references requests(id) on delete cascade,
  old_status request_status,
  new_status request_status,
  changed_by text,
  reason text,
  created_at timestamptz default now()
);
create index if not exists idx_status_history_req on request_status_history(request_id);

create table if not exists driver_search_logs (
  id bigserial primary key,
  driver_id bigint references drivers(id) on delete cascade,
  query text,
  viewed_request_id uuid,
  created_at timestamptz default now()
);

create table if not exists admin_alerts (
  id bigserial primary key,
  alert_type alert_type not null,
  details jsonb,
  is_dismissed boolean default false,
  created_at timestamptz default now()
);

create table if not exists system_settings (
  id int primary key default 1,
  passenger_min int default 1,
  passenger_max int default 7,
  designations text[] default array['Staff','Nurse','Driver','Manager'],
  hours_open time default '08:00',
  hours_close time default '20:00',
  slot_minutes int default 30 check (slot_minutes in (15,30,60)),
  auto_delete_after_days int,
  updated_at timestamptz default now()
);
insert into system_settings (id) values (1) on conflict (id) do nothing;

create table if not exists driver_sessions (
  id bigserial primary key,
  driver_id bigint references drivers(id) on delete cascade,
  session_token text unique not null,
  expires_at timestamptz not null,
  created_at timestamptz default now()
);
create index if not exists idx_driver_sessions_token on driver_sessions(session_token);

-- RLS: enable and deny all by default
alter table employees enable row level security;
alter table drivers enable row level security;
alter table cars enable row level security;
alter table driver_car_assignments enable row level security;
alter table requests enable row level security;
alter table request_status_history enable row level security;
alter table driver_search_logs enable row level security;
alter table admin_alerts enable row level security;
alter table system_settings enable row level security;
alter table driver_sessions enable row level security;

-- drop old policies to avoid duplicates
DROP POLICY IF EXISTS "deny anon employees" ON employees;
DROP POLICY IF EXISTS "deny anon drivers" ON drivers;
DROP POLICY IF EXISTS "deny anon cars" ON cars;
DROP POLICY IF EXISTS "deny anon driver_car" ON driver_car_assignments;
DROP POLICY IF EXISTS "deny anon requests" ON requests;
DROP POLICY IF EXISTS "deny anon history" ON request_status_history;
DROP POLICY IF EXISTS "deny anon dlogs" ON driver_search_logs;
DROP POLICY IF EXISTS "deny anon alerts" ON admin_alerts;
DROP POLICY IF EXISTS "deny anon settings" ON system_settings;
DROP POLICY IF EXISTS "deny anon dsessions" ON driver_sessions;

create policy "deny anon employees" on employees for all using (false);
create policy "deny anon drivers" on drivers for all using (false);
create policy "deny anon cars" on cars for all using (false);
create policy "deny anon driver_car" on driver_car_assignments for all using (false);
create policy "deny anon requests" on requests for all using (false);
create policy "deny anon history" on request_status_history for all using (false);
create policy "deny anon dlogs" on driver_search_logs for all using (false);
create policy "deny anon alerts" on admin_alerts for all using (false);
create policy "deny anon settings" on system_settings for all using (false);
create policy "deny anon dsessions" on driver_sessions for all using (false);

-- HELPER FUNCTIONS
create or replace function norm_text(t text) returns text
language sql immutable as $$
  select trim(lower(t));
$$;

create or replace function validate_employee(p_employee_id text, p_full_name text)
returns boolean
language plpgsql
security definer
as $$
declare ok boolean;
begin
  select exists(
    select 1 from employees
    where is_active
      and norm_text(employee_id)=norm_text(p_employee_id)
      and norm_text(full_name)=norm_text(p_full_name)
  ) into ok;
  return ok;
end;
$$;

-- check if designation is allowed (case-insensitive)
create or replace function designation_allowed(p_designation text)
returns boolean
language sql
security definer
as $$
  select exists (
    select 1 from system_settings
    where id=1 and lower(p_designation) = any (select lower(x) from unnest(designations) as x)
  );
$$;

-- fetch system settings
create or replace function get_system_settings()
returns jsonb
language plpgsql
security definer
as $$
declare js jsonb;
begin
  select jsonb_build_object(
    'passenger_min', passenger_min,
    'passenger_max', passenger_max,
    'designations', designations,
    'hours_open', hours_open,
    'hours_close', hours_close,
    'slot_minutes', slot_minutes
  ) into js
  from system_settings
  where id = 1;
  return js;
end;
$$;

-- create request with validations
create or replace function create_request(
  p_employee_id text, p_full_name text, p_phone text, p_designation text,
  p_passengers int, p_purpose text, p_note text,
  p_pickup jsonb, p_dropoff jsonb, p_requested_at timestamptz
)
returns uuid
language plpgsql
security definer
as $$
declare
  pmin int; pmax int; sopen time; sclose time; sm int;
  req_id uuid;
  req_time time;
begin
  select passenger_min, passenger_max, hours_open, hours_close, slot_minutes
    into pmin, pmax, sopen, sclose, sm
  from system_settings where id = 1;

  if not validate_employee(p_employee_id, p_full_name) then
    raise exception 'Invalid employee';
  end if;

  if not designation_allowed(p_designation) then
    raise exception 'Invalid designation';
  end if;

  -- phone must match UAE format +971...
  if p_phone !~ '^\+971\d{8,9}$' then
    raise exception 'Invalid phone number';
  end if;

  if p_passengers < pmin or p_passengers > pmax then
    raise exception 'Passengers out of allowed range (% to %)', pmin, pmax;
  end if;

  if p_requested_at <= now() then
    raise exception 'Cannot book past time';
  end if;

  req_time := (p_requested_at at time zone 'UTC')::time;
  -- hours open/close check
  if req_time < sopen or req_time > sclose then
    raise exception 'Requested time outside operating hours';
  end if;

  -- check minute increments
  if (extract(minute from p_requested_at)::int % sm) <> 0 or (extract(second from p_requested_at)::int) <> 0 then
    raise exception 'Time must align with slot increments';
  end if;

  insert into requests(
    employee_id, full_name, phone, designation,
    passengers, purpose, note,
    pickup_location, dropoff_location, requested_at, status
  ) values (
    p_employee_id, p_full_name, p_phone, p_designation,
    p_passengers, p_purpose, p_note,
    p_pickup, p_dropoff, p_requested_at, 'Assigning'
  ) returning id into req_id;

  insert into request_status_history(request_id, old_status, new_status, changed_by)
  values (req_id, null, 'Assigning', 'employee');
  return req_id;
end;
$$;

create or replace function get_requests_by_phone(p_phone text)
returns setof requests
language sql
security definer
as $$
  select * from requests where phone = p_phone order by created_at desc;
$$;

create or replace function get_request_by_id(p_id uuid)
returns requests
language sql
security definer
as $$
  select * from requests where id = p_id;
$$;

create or replace function cancel_request(p_id uuid, p_phone text)
returns boolean
language plpgsql
security definer
as $$
declare old request_status;
begin
  select status into old from requests where id=p_id and phone=p_phone;
  if not found then
    return false;
  end if;
  update requests set status='Canceled', status_updated_at=now() where id=p_id and phone=p_phone;
  insert into request_status_history(request_id, old_status, new_status, changed_by)
  values (p_id, old, 'Canceled', 'employee');
  return true;
end;
$$;

create or replace function driver_login(p_employee_id text, p_password_hash text)
returns table(session_token text, driver_id bigint, expires_at timestamptz)
language plpgsql
security definer
as $$
declare did bigint; tok text; exp timestamptz := now() + interval '7 days';
begin
  select id into did from drivers
  where is_active and norm_text(employee_id)=norm_text(p_employee_id)
    and password_hash = p_password_hash;
  if not found then
    return;
  end if;
  tok := encode(gen_random_bytes(24),'hex');
  insert into driver_sessions(driver_id, session_token, expires_at)
  values (did, tok, exp);
  return query select tok, did, exp;
end;
$$;

create or replace function verify_driver_session(p_token text)
returns bigint
language plpgsql
security definer
as $$
declare did bigint;
begin
  select driver_id into did from driver_sessions
  where session_token=p_token and expires_at>now();
  return did;
end;
$$;

create or replace function get_driver_requests(
  p_session_token text,
  p_query text default null
)
returns setof requests
language plpgsql
security definer
as $$
declare did bigint;
begin
  did := verify_driver_session(p_session_token);
  if did is null then
    return;
  end if;
  return query
  select r.*
  from requests r
  where r.assigned_driver_id = did
    and (
      p_query is null
      or norm_text(cast(r.id as text)) like '%'||norm_text(p_query)||'%'
      or norm_text(coalesce(r.purpose,'')) like '%'||norm_text(p_query)||'%'
      or norm_text(coalesce(r.full_name,'')) like '%'||norm_text(p_query)||'%'
    )
  order by r.created_at desc;
end;
$$;

create or replace function driver_update_request(
  p_session_token text,
  p_request_id uuid,
  p_action text,
  p_eta_minutes int,
  p_reason text,
  p_status request_status
)
returns boolean
language plpgsql
security definer
as $$
declare did bigint; old request_status;
begin
  did := verify_driver_session(p_session_token);
  if did is null then
    return false;
  end if;
  select status into old from requests where id = p_request_id;
  if not found then return false; end if;

  if p_action = 'accept' then
    update requests set status='Assigned', status_updated_at=now(), assigned_driver_id=did
      where id = p_request_id;
    insert into request_status_history(request_id, old_status, new_status, changed_by, reason)
      values (p_request_id, old, 'Assigned', 'driver:'||did::text, 'ETA:'||coalesce(p_eta_minutes,0));
    return true;

  elsif p_action = 'reject' then
    update requests set status='Rejected', status_updated_at=now()
      where id = p_request_id;
    insert into request_status_history(request_id, old_status, new_status, changed_by, reason)
      values (p_request_id, old, 'Rejected', 'driver:'||did::text, p_reason);
    return true;

  elsif p_action = 'status' then
    update requests set status=p_status, status_updated_at=now()
      where id = p_request_id;
    insert into request_status_history(request_id, old_status, new_status, changed_by)
      values (p_request_id, old, p_status, 'driver:'||did::text);

    if p_status = 'Completed' then
      if exists (
        select 1
        from request_status_history h1
        join request_status_history h2 on h2.request_id=h1.request_id
        where h1.request_id = p_request_id
          and h1.new_status = 'Started'
          and h2.new_status = 'Completed'
          and h2.created_at - h1.created_at >= interval '60 minutes'
      ) then
        insert into admin_alerts(alert_type, details)
        values ('LongTrip', jsonb_build_object('request_id', p_request_id));
      end if;
    end if;
    return true;
  end if;

  return false;
end;
$$;

create or replace function log_driver_search(p_session_token text, p_query text, p_viewed_request uuid)
returns boolean
language plpgsql
security definer
as $$
declare did bigint; r_created timestamptz;
begin
  did := verify_driver_session(p_session_token);
  if did is null then
    return false;
  end if;
  insert into driver_search_logs(driver_id, query, viewed_request_id)
  values (did, p_query, p_viewed_request);
  if p_viewed_request is not null then
    select created_at into r_created from requests where id=p_viewed_request;
    if r_created < now() - interval '2 days' then
      insert into admin_alerts(alert_type, details)
      values ('OldRequestViewed', jsonb_build_object('request_id', p_viewed_request, 'driver_id', did));
    end if;
  end if;
  return true;
end;
$$;

-- End of full schema

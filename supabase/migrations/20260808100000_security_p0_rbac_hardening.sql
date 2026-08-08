-- Relay Rider P0 security hardening: enforce a strict organization role hierarchy.
-- Closes the path where broad organization managers could assign more privileged roles.

create or replace function private.can_manage_members(org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_catalog
as $$
  select private.has_org_role(org_id, array['owner','admin']);
$$;

create or replace function private.can_assign_role(org_id uuid, requested_role text)
returns boolean
language plpgsql
stable
security definer
set search_path = public, pg_catalog
as $$
declare
  caller_role text;
begin
  select m.role into caller_role
  from public.organization_members m
  where m.organization_id = org_id
    and m.user_id = auth.uid()
    and m.status = 'active'
  limit 1;

  if caller_role is null then return false; end if;

  if caller_role = 'owner' then
    return requested_role in (
      'owner','admin','program_admin','tdm_manager','sustainability_manager',
      'site_manager','analyst','reviewer','participant'
    );
  end if;

  if caller_role = 'admin' then
    return requested_role in (
      'program_admin','tdm_manager','sustainability_manager',
      'site_manager','analyst','reviewer','participant'
    );
  end if;

  return false;
end;
$$;

create or replace function public.create_organization_invitation(
  org_id uuid,
  invite_email text,
  invite_role text,
  invite_site_id uuid default null,
  invite_site_role text default null,
  invite_cohort_id uuid default null,
  expires_days integer default 7
)
returns table(invitation_id uuid, invite_token text, expires_at timestamptz)
language plpgsql
security definer
set search_path = public, private, pg_catalog
as $$
declare
  uid uuid := auth.uid();
  clean_email text := lower(trim(invite_email));
  raw_token text;
  token_digest text;
  expiry timestamptz;
  new_id uuid;
begin
  if uid is null then raise exception 'Authentication required'; end if;
  if not private.can_manage_members(org_id) then raise exception 'Organization member-management permission required'; end if;
  if not private.can_assign_role(org_id, invite_role) then raise exception 'You may not assign the requested organization role'; end if;
  if clean_email = '' or position('@' in clean_email) <= 1 then raise exception 'Valid invitation email required'; end if;
  if invite_role not in ('owner','admin','program_admin','tdm_manager','sustainability_manager','site_manager','analyst','reviewer','participant') then raise exception 'Unsupported invitation role'; end if;
  if invite_site_role is not null and invite_site_role not in ('site_member','site_manager','analyst','reviewer','participant') then raise exception 'Unsupported site role'; end if;
  if invite_site_id is not null and not exists (select 1 from public.organization_sites s where s.id = invite_site_id and s.organization_id = org_id) then raise exception 'Site does not belong to organization'; end if;
  if invite_cohort_id is not null and not exists (select 1 from public.cohorts c where c.id = invite_cohort_id and c.organization_id = org_id) then raise exception 'Cohort does not belong to organization'; end if;

  update public.organization_invitations
  set status = case when expires_at <= now() then 'expired' else 'revoked' end,
      updated_at = now()
  where organization_id = org_id
    and lower(invited_email) = clean_email
    and status = 'pending';

  raw_token := encode(gen_random_bytes(32),'hex');
  token_digest := encode(digest(raw_token,'sha256'),'hex');
  expiry := now() + make_interval(days => greatest(1,least(coalesce(expires_days,7),30)));

  insert into public.organization_invitations(
    organization_id, invited_email, role, site_id, site_role, cohort_id,
    token_hash, expires_at, invited_by
  ) values (
    org_id, clean_email, invite_role, invite_site_id, invite_site_role, invite_cohort_id,
    token_digest, expiry, uid
  ) returning id into new_id;

  invitation_id := new_id;
  invite_token := raw_token;
  expires_at := expiry;
  return next;
end;
$$;

revoke all on function public.create_organization_invitation(uuid,text,text,uuid,text,uuid,integer) from public, anon;
grant execute on function public.create_organization_invitation(uuid,text,text,uuid,text,uuid,integer) to authenticated;

create or replace function public.update_organization_member(
  org_id uuid,
  target_user_id uuid,
  new_role text,
  new_status text
)
returns void
language plpgsql
security definer
set search_path = public, private, pg_catalog
as $$
declare
  uid uuid := auth.uid();
  current_role text;
  active_owner_count integer;
begin
  if uid is null then raise exception 'Authentication required'; end if;
  if not private.can_manage_members(org_id) then raise exception 'Organization member-management permission required'; end if;
  if new_role not in ('owner','admin','program_admin','tdm_manager','sustainability_manager','site_manager','analyst','reviewer','participant') then raise exception 'Unsupported role'; end if;
  if new_status not in ('active','invited','suspended','disabled') then raise exception 'Unsupported member status'; end if;

  select role into current_role
  from public.organization_members
  where organization_id = org_id and user_id = target_user_id
  for update;

  if current_role is null then raise exception 'Organization member not found'; end if;
  if current_role = 'owner' and not private.has_org_role(org_id, array['owner']) then raise exception 'Only an owner can modify another owner'; end if;
  if not private.can_assign_role(org_id, new_role) then raise exception 'You may not assign the requested organization role'; end if;

  if current_role = 'owner' and (new_role <> 'owner' or new_status <> 'active') then
    select count(*) into active_owner_count
    from public.organization_members
    where organization_id = org_id and role = 'owner' and status = 'active';
    if active_owner_count <= 1 then raise exception 'Organization must retain at least one active owner'; end if;
  end if;

  update public.organization_members
  set role = new_role, status = new_status
  where organization_id = org_id and user_id = target_user_id;
end;
$$;

revoke all on function public.update_organization_member(uuid,uuid,text,text) from public, anon;
grant execute on function public.update_organization_member(uuid,uuid,text,text) to authenticated;

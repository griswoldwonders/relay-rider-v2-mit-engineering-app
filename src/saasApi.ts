const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL ?? "https://dzrqrqfxcihvufvyctbt.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ?? "sb_publishable_hLCfTlWFEQRkwKUwz5Wv2g_DwoVqPy1";
const SESSION_KEY = "relay-rider-saas-session-v1";

export type SaasUser = { id: string; email?: string };
export type SaasSession = { access_token: string; refresh_token: string; expires_at: number; user: SaasUser };
export type Organization = { id: string; name: string; organization_type: string; status: string; slug: string | null; onboarding_completed_at: string | null };
export type Membership = { organization_id: string; user_id: string; role: string; status: string };
export type OrganizationSite = { id: string; organization_id: string; name: string; site_type: string; address_label: string | null; general_zone: string | null; timezone: string; parking_capacity: number | null; is_active: boolean };
export type Cohort = { id: string; organization_id: string; site_id: string | null; name: string; description: string | null; eligibility_rules: Record<string, unknown>; is_active: boolean };
export type TdmProgram = { id: string; organization_id: string; name: string; program_type: string; objective: string | null; status: string; reporting_period_start: string | null; reporting_period_end: string | null };
export type DataSource = { id: string; organization_id: string; site_id: string | null; name: string; source_type: string; status: string; last_synced_at: string | null; coverage_summary: string | null };
export type Onboarding = { organization_id: string; organization_profile_complete: boolean; site_configured: boolean; cohort_configured: boolean; program_configured: boolean; participant_path_configured: boolean; data_source_reviewed: boolean; completed_at: string | null };
export type ParticipantDirectoryRow = { user_id: string; membership_role: string; membership_status: string; participant_type: string; commuter_need_count: number; planned_route_count: number; latest_signal_at: string | null };
export type AuditEvent = { id: number; occurred_at: string; actor_user_id: string | null; table_name: string; operation: string; row_id: string | null; changed_columns: string[] };

type ApiError = { message?: string; error_description?: string; msg?: string; details?: string; hint?: string };

function headers(token?: string) {
  return {
    apikey: SUPABASE_PUBLISHABLE_KEY,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    "Content-Type": "application/json",
  };
}

function publicErrorMessage(status: number, err: ApiError) {
  if (status === 400 && (err.message || err.error_description || err.msg)) {
    return err.message ?? err.error_description ?? err.msg ?? "Invalid request.";
  }
  if (status === 401) return "Your session is no longer valid. Please sign in again.";
  if (status === 403) return "You do not have permission to perform this action.";
  if (status === 404) return "The requested record was not found.";
  if (status === 409) return "That change conflicts with an existing record.";
  if (status === 429) return "Too many requests. Please wait and try again.";
  return `Request failed (${status}).`;
}

async function parse<T>(response: Response): Promise<T> {
  const raw = await response.text();
  let body: unknown = null;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new Error(publicErrorMessage(response.status, (body ?? {}) as ApiError));
  }
  return body as T;
}

function sessionStorageSafe() {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function clearLegacyPersistentSession() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(SESSION_KEY);
  } catch {
    // Ignore storage access errors in privacy-restricted browsers.
  }
}

function saveSession(session: SaasSession | null) {
  const storage = sessionStorageSafe();
  if (!storage) return;
  if (session) storage.setItem(SESSION_KEY, JSON.stringify(session));
  else storage.removeItem(SESSION_KEY);
  clearLegacyPersistentSession();
}

function readStoredSession() {
  const storage = sessionStorageSafe();
  if (!storage) return null;
  const ephemeral = storage.getItem(SESSION_KEY);
  if (ephemeral) return ephemeral;

  // One-time migration: remove sessions previously persisted in localStorage.
  try {
    const legacy = window.localStorage.getItem(SESSION_KEY);
    if (legacy) {
      storage.setItem(SESSION_KEY, legacy);
      window.localStorage.removeItem(SESSION_KEY);
      return legacy;
    }
  } catch {
    // Ignore storage access errors.
  }
  return null;
}

function normalizeSession(payload: any): SaasSession | null {
  if (!payload?.access_token || !payload?.refresh_token || !payload?.user?.id) return null;
  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    expires_at: payload.expires_at ?? Math.floor(Date.now() / 1000) + (payload.expires_in ?? 3600),
    user: { id: payload.user.id, email: payload.user.email },
  };
}

export async function signIn(email: string, password: string) {
  const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, { method: "POST", headers: headers(), body: JSON.stringify({ email, password }) });
  const payload = await parse<any>(response);
  const session = normalizeSession(payload);
  if (!session) throw new Error("Supabase did not return an authenticated session.");
  saveSession(session);
  return session;
}

export async function signUp(email: string, password: string) {
  const response = await fetch(`${SUPABASE_URL}/auth/v1/signup`, { method: "POST", headers: headers(), body: JSON.stringify({ email, password }) });
  const payload = await parse<any>(response);
  const session = normalizeSession(payload);
  if (session) saveSession(session);
  return { session, user: payload?.user as SaasUser | undefined };
}

export async function restoreSession(): Promise<SaasSession | null> {
  if (typeof window === "undefined") return null;
  const stored = readStoredSession();
  if (!stored) return null;
  try {
    const session = JSON.parse(stored) as SaasSession;
    if (!session.refresh_token) {
      saveSession(null);
      return null;
    }
    if (session.expires_at > Math.floor(Date.now() / 1000) + 90) return session;
    const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, { method: "POST", headers: headers(), body: JSON.stringify({ refresh_token: session.refresh_token }) });
    const payload = await parse<any>(response);
    const refreshed = normalizeSession(payload);
    saveSession(refreshed);
    return refreshed;
  } catch {
    saveSession(null);
    return null;
  }
}

export async function signOut(session: SaasSession | null) {
  try {
    if (session?.access_token) await fetch(`${SUPABASE_URL}/auth/v1/logout`, { method: "POST", headers: headers(session.access_token) });
  } finally {
    saveSession(null);
  }
}

async function rest<T>(session: SaasSession, path: string, init?: RequestInit) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { ...init, headers: { ...headers(session.access_token), Prefer: "return=representation", ...(init?.headers ?? {}) } });
  return parse<T>(response);
}

export function listOrganizations(session: SaasSession) {
  return rest<Organization[]>(session, "organizations?select=id,name,organization_type,status,slug,onboarding_completed_at&order=created_at.asc");
}

export function listMemberships(session: SaasSession) {
  return rest<Membership[]>(session, "organization_members?select=organization_id,user_id,role,status");
}

export async function createOrganization(session: SaasSession, name: string, organizationType: string) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/create_organization_with_owner`, { method: "POST", headers: headers(session.access_token), body: JSON.stringify({ org_name: name, org_type: organizationType, requested_slug: null }) });
  return parse<string>(response);
}

export function listSites(session: SaasSession, organizationId: string) {
  return rest<OrganizationSite[]>(session, `organization_sites?organization_id=eq.${organizationId}&select=id,organization_id,name,site_type,address_label,general_zone,timezone,parking_capacity,is_active&order=created_at.asc`);
}

export function createSite(session: SaasSession, organizationId: string, input: { name: string; site_type: string; address_label?: string; general_zone?: string; parking_capacity?: number | null }) {
  return rest<OrganizationSite[]>(session, "organization_sites", { method: "POST", body: JSON.stringify({ organization_id: organizationId, ...input, created_by: session.user.id }) });
}

export function listCohorts(session: SaasSession, organizationId: string) {
  return rest<Cohort[]>(session, `cohorts?organization_id=eq.${organizationId}&select=id,organization_id,site_id,name,description,eligibility_rules,is_active&order=created_at.asc`);
}

export function createCohort(session: SaasSession, organizationId: string, input: { name: string; description?: string; site_id?: string | null }) {
  return rest<Cohort[]>(session, "cohorts", { method: "POST", body: JSON.stringify({ organization_id: organizationId, name: input.name, description: input.description ?? null, site_id: input.site_id ?? null, eligibility_rules: {} }) });
}

export function listPrograms(session: SaasSession, organizationId: string) {
  return rest<TdmProgram[]>(session, `tdm_programs?organization_id=eq.${organizationId}&select=id,organization_id,name,program_type,objective,status,reporting_period_start,reporting_period_end&order=created_at.asc`);
}

export function createProgram(session: SaasSession, organizationId: string, input: { name: string; program_type: string; objective?: string }) {
  return rest<TdmProgram[]>(session, "tdm_programs", { method: "POST", body: JSON.stringify({ organization_id: organizationId, name: input.name, program_type: input.program_type, objective: input.objective ?? null, status: "draft", created_by: session.user.id }) });
}

export function listDataSources(session: SaasSession, organizationId: string) {
  return rest<DataSource[]>(session, `data_sources?organization_id=eq.${organizationId}&select=id,organization_id,site_id,name,source_type,status,last_synced_at,coverage_summary&order=created_at.asc`);
}

export function createDataSource(session: SaasSession, organizationId: string, input: { name: string; source_type: string; site_id?: string | null }) {
  return rest<DataSource[]>(session, "data_sources", { method: "POST", body: JSON.stringify({ organization_id: organizationId, name: input.name, source_type: input.source_type, site_id: input.site_id ?? null, status: input.source_type === "participant_intake" ? "configured" : "not_connected", created_by: session.user.id }) });
}

export function getOnboarding(session: SaasSession, organizationId: string) {
  return rest<Onboarding[]>(session, `organization_onboarding?organization_id=eq.${organizationId}&select=*`);
}

export function updateOnboarding(session: SaasSession, organizationId: string, patch: Partial<Onboarding>) {
  return rest<Onboarding[]>(session, `organization_onboarding?organization_id=eq.${organizationId}`, { method: "PATCH", body: JSON.stringify(patch) });
}

export async function getParticipantDirectory(session: SaasSession, organizationId: string) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_participant_directory`, { method: "POST", headers: headers(session.access_token), body: JSON.stringify({ org_id: organizationId }) });
  return parse<ParticipantDirectoryRow[]>(response);
}

export async function getAuditEvents(session: SaasSession, organizationId: string) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/get_organization_audit_events`, { method: "POST", headers: headers(session.access_token), body: JSON.stringify({ org_id: organizationId, limit_count: 100 }) });
  return parse<AuditEvent[]>(response);
}

// admin-api — Supabase Edge Function
// بتعمل العمليات اللي محتاجة صلاحية السيرفر: إنشاء شركات ومستخدمين، وتغيير كلمات السر، والحذف.
// المفتاح السري بيفضل هنا على السيرفر ومش بيوصل للمتصفح أبدًا.
import { createClient } from 'npm:@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
function secretKey(): string {
  try {
    const k = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}');
    if (k && k.default) return k.default;
  } catch (_e) { /* fall through */ }
  return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
}
const admin = createClient(SUPABASE_URL, secretKey(), { auth: { persistSession: false, autoRefreshToken: false } });

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
class HttpErr extends Error { status: number; constructor(m: string, s = 400) { super(m); this.status = s; } }

// نفس المعادلة اللي في المتصفح بالظبط: بنحوّل (رقم الشركة + اسم المستخدم) لإيميل داخلي ثابت.
// الدومين الافتراضي cvs-app.example.com. لو Supabase رفضه ممكن تغيّره (هنا بمتغير EMAIL_DOMAIN وفي config.js بـ emailDomain) بشرط يبقى نفسه في الاتنين.
async function emailFor(cid: number, username: string): Promise<string> {
  const data = new TextEncoder().encode(`${cid}:${String(username).trim().toLowerCase()}`);
  const buf = await crypto.subtle.digest('SHA-256', data);
  const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
  return `u${hex}@${Deno.env.get('EMAIL_DOMAIN') || 'cvs-app.example.com'}`;
}
const normCode = (s: string) => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

async function caller(req: Request) {
  const jwt = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!jwt) throw new HttpErr('unauthorized', 401);
  const { data, error } = await admin.auth.getUser(jwt);
  if (error || !data || !data.user) throw new HttpErr('unauthorized', 401);
  const { data: p } = await admin.from('profiles').select('id,cid,role,active,username').eq('id', data.user.id).maybeSingle();
  if (!p || !p.active) throw new HttpErr('forbidden', 403);
  if (p.role !== 'super') {
    const { data: c } = await admin.from('companies').select('active,expires').eq('id', p.cid).maybeSingle();
    const today = new Date().toISOString().slice(0, 10);
    if (!c || !c.active || (c.expires && c.expires < today)) throw new HttpErr('company_inactive', 403);
  }
  return p;
}

async function targetProfile(me: any, userId: string) {
  const { data: t } = await admin.from('profiles').select('id,cid,role,username').eq('id', userId).maybeSingle();
  if (!t) throw new HttpErr('not_found', 404);
  if (me.role === 'super') return t;
  if (me.role === 'cadmin' && t.cid === me.cid && t.role === 'user') return t;
  throw new HttpErr('forbidden', 403);
}
const needPw = (p: string) => { if (!p || String(p).length < 6) throw new HttpErr('password_too_short'); };
const needUser = (u: string) => { if (!u || !String(u).trim()) throw new HttpErr('username_required'); };

async function createAccount(cid: number, role: string, username: string, name: string, password: string, perms: unknown) {
  const email = await emailFor(cid, username);
  const { data: created, error } = await admin.auth.admin.createUser({
    email, password, email_confirm: true, user_metadata: { username, cid },
  });
  if (error || !created || !created.user) throw new HttpErr(error && /already|registered|exists/i.test(error.message) ? 'username_taken' : (error ? error.message : 'create_failed'));
  const { error: pe } = await admin.from('profiles').insert({
    id: created.user.id, cid, role, username: String(username).trim(), name: name || String(username).trim(), perms: perms || {},
  });
  if (pe) {
    await admin.auth.admin.deleteUser(created.user.id);
    throw new HttpErr(/duplicate|unique/i.test(pe.message) ? 'username_taken' : pe.message);
  }
  return created.user.id as string;
}

async function removeStoragePrefix(cid: number) {
  const bucket = admin.storage.from('cvfiles');
  for (let guard = 0; guard < 500; guard++) {
    const { data } = await bucket.list(String(cid), { limit: 1000 });
    if (!data || !data.length) break;
    await bucket.remove(data.map((f: any) => `${cid}/${f.name}`));
    if (data.length < 1000) break;
  }
}

const actions: Record<string, (me: any, b: any) => Promise<unknown>> = {
  async create_company(me, b) {
    if (me.role !== 'super') throw new HttpErr('forbidden', 403);
    const name = String(b.name || '').trim(); const code = normCode(b.code);
    if (!name) throw new HttpErr('name_required'); if (code.length < 3) throw new HttpErr('code_too_short');
    needUser(b.admin_username); needPw(b.admin_password);
    const { data: ex } = await admin.from('companies').select('id').ilike('code', code).maybeSingle();
    if (ex) throw new HttpErr('code_taken');
    const { data: co, error } = await admin.from('companies').insert({
      code, name, max_users: Math.max(0, +b.max_users || 0), max_cands: Math.max(0, +b.max_cands || 0), expires: b.expires || null,
    }).select().single();
    if (error) throw new HttpErr(/duplicate|unique/i.test(error.message) ? 'code_taken' : error.message);
    try {
      await admin.from('company_settings').insert({ cid: co.id, data: b.settings || { company: name, logo: '' } });
      await createAccount(co.id, 'cadmin', b.admin_username, b.admin_name || `Admin ${name}`, b.admin_password, {});
    } catch (e) {
      await admin.from('companies').delete().eq('id', co.id);
      throw e;
    }
    return { company: co };
  },

  async create_user(me, b) {
    const role = b.role === 'cadmin' ? 'cadmin' : 'user';
    let cid = me.role === 'super' ? +b.cid : me.cid;
    if (!cid) throw new HttpErr('cid_required');
    if (me.role === 'cadmin' && role !== 'user') throw new HttpErr('forbidden', 403);
    if (me.role === 'cadmin' && cid !== me.cid) throw new HttpErr('forbidden', 403);
    needUser(b.username); needPw(b.password);
    const { data: co } = await admin.from('companies').select('id,max_users').eq('id', cid).maybeSingle();
    if (!co) throw new HttpErr('company_not_found', 404);
    if (co.max_users > 0) {
      const { count } = await admin.from('profiles').select('id', { count: 'exact', head: true }).eq('cid', cid);
      if ((count || 0) >= co.max_users) throw new HttpErr('user_limit');
    }
    const id = await createAccount(cid, role, b.username, b.name, b.password, role === 'user' ? b.perms : {});
    return { id };
  },

  async set_password(me, b) {
    const t = await targetProfile(me, b.user_id); needPw(b.password);
    const { error } = await admin.auth.admin.updateUserById(t.id, { password: b.password });
    if (error) throw new HttpErr(error.message);
    return { ok: true };
  },

  async delete_user(me, b) {
    const t = await targetProfile(me, b.user_id);
    if (t.id === me.id) throw new HttpErr('cannot_delete_self');
    const { error } = await admin.auth.admin.deleteUser(t.id);
    if (error) throw new HttpErr(error.message);
    return { ok: true };
  },

  async delete_company(me, b) {
    if (me.role !== 'super') throw new HttpErr('forbidden', 403);
    const cid = +b.cid; if (!cid) throw new HttpErr('cid_required');
    const { data: ps } = await admin.from('profiles').select('id').eq('cid', cid);
    for (const p of ps || []) await admin.auth.admin.deleteUser(p.id);
    await removeStoragePrefix(cid);
    const { error } = await admin.from('companies').delete().eq('id', cid);
    if (error) throw new HttpErr(error.message);
    return { ok: true };
  },

  async purge_company_files(me, b) {            // بتتنادى عند «مسح كل بيانات الشركة»
    const cid = me.role === 'super' ? +b.cid : me.cid;
    if (me.role === 'user' || !cid) throw new HttpErr('forbidden', 403);
    await removeStoragePrefix(cid);
    return { ok: true };
  },
};

export async function handle(req: Request): Promise<Response> {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  try {
    const me = await caller(req);
    if (me.role === 'user') throw new HttpErr('forbidden', 403);   // المستخدم العادي ممنوع من كل عمليات الإدارة
    const body = await req.json().catch(() => ({}));
    const fn = actions[body.action];
    if (!fn) throw new HttpErr('unknown_action');
    return json(await fn(me, body));
  } catch (e) {
    const err = e as HttpErr;
    return json({ error: err.message || 'error' }, err.status || 400);
  }
}
Deno.serve(handle);

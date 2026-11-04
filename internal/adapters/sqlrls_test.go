package adapters

import (
	"strings"
	"testing"
)

const rlsTable = "create table public.profiles (\n  id uuid primary key references auth.users on delete cascade,\n  display_name text,\n  is_admin boolean not null default false\n);\nalter table public.profiles enable row level security;\n"

const rlsUpdatePolicy = "create policy p on public.profiles for update using (id = auth.uid());\n"

func rlsHits(t *testing.T, files map[string]string) []string {
	t.Helper()
	files["src/app.js"] = "export const x = 1;\n"
	var out []string
	for _, s := range runOn(t, codeAdapter{}, files) {
		if s.RuleID == "sql.rls-update-privileged-column" {
			out = append(out, s.File+":"+s.Key)
		}
	}
	return out
}

func TestRLSUpdatePrivilegedColumnFires(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"single migration": {"supabase/migrations/0001_init.sql": rlsTable + rlsUpdatePolicy},
		"split across migrations": {
			"db/migrations/0001_profiles.sql": "create table profiles (id uuid primary key, display_name text);\n",
			"db/migrations/0002_admin.sql":    "alter table profiles add column if not exists is_admin boolean default false;\n",
			"db/migrations/0003_policy.sql":   "-- users edit their own profile\ncreate policy \"Own profile\" on profiles\n  for all to authenticated\n  using ((select auth.uid()) = id);\n",
		},
		"check without the column": {"supabase/migrations/1.sql": "create table accounts (id uuid, user_id uuid, credits int);\ncreate policy \"own\" on accounts as permissive for update using (user_id = auth.uid()) with check (user_id = auth.uid());\n"},
	} {
		got := rlsHits(t, files)
		if len(got) != 1 {
			t.Errorf("%s: want one finding, got %v", name, got)
		}
	}
	got := rlsHits(t, map[string]string{"supabase/migrations/0001_init.sql": rlsTable + rlsUpdatePolicy})
	if len(got) != 1 || got[0] != "supabase/migrations/0001_init.sql:public.profiles.is_admin" {
		t.Fatalf("finding = %v", got)
	}
}

func TestRLSUpdatePrivilegedColumnSilent(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"revoke and column grant": {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy +
			"revoke update on profiles from authenticated;\ngrant update (display_name) on profiles to authenticated;\n"},
		"revoke only":                 {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy + "revoke update on table public.profiles from authenticated, anon;\n"},
		"revoke all tables in schema": {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy + "revoke all on all tables in schema public from authenticated;\n"},
		"revoke in a later file": {
			"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy,
			"supabase/migrations/0002.sql": "revoke update (is_admin) on public.profiles from authenticated;\n",
		},
		"before update trigger": {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy +
			"create trigger protect_admin before update of is_admin on public.profiles for each row execute function guard();\n"},
		"trigger in a function body": {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy +
			"do $$ begin execute 'create trigger g before insert or update on profiles for each row execute function guard()'; end $$;\n"},
		"policy dropped later": {
			"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy,
			"supabase/migrations/0002.sql": "drop policy if exists p on public.profiles;\n",
		},
		"no privileged column": {"supabase/migrations/0001.sql": "create table notes (id uuid, owner uuid, body text);\ncreate policy p on notes for update using (owner = auth.uid());\n"},
		"select policy":        {"supabase/migrations/0001.sql": rlsTable + "create policy p on public.profiles for select using (id = auth.uid());\n"},
		"no explicit command":  {"supabase/migrations/0001.sql": rlsTable + "create policy p on public.profiles using (id = auth.uid());\n"},
		"restrictive":          {"supabase/migrations/0001.sql": rlsTable + "create policy p on public.profiles as restrictive for update using (id = auth.uid());\n"},
		"service role only":    {"supabase/migrations/0001.sql": rlsTable + "create policy p on public.profiles for update to service_role using (id = auth.uid());\n"},
		"no auth.uid":          {"supabase/migrations/0001.sql": rlsTable + "create policy p on public.profiles for update using (false);\n"},
		"check pins the column": {"supabase/migrations/0001.sql": rlsTable +
			"create policy p on public.profiles for update using (id = auth.uid()) with check (id = auth.uid() and is_admin = false);\n"},
		"column dropped": {
			"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy,
			"supabase/migrations/0002.sql": "alter table public.profiles drop column is_admin;\n",
		},
		"generated column":         {"supabase/migrations/0001.sql": "create table t (id uuid, tier text generated always as ('free') stored);\ncreate policy p on t for update using (id = auth.uid());\n"},
		"table in another schema":  {"supabase/migrations/0001.sql": "create table private.profiles (id uuid, role text);\ncreate policy p on public.profiles for update using (id = auth.uid());\n"},
		"table unknown":            {"supabase/migrations/0001.sql": rlsUpdatePolicy},
		"policy only in a comment": {"supabase/migrations/0001.sql": rlsTable + "/* create policy p on public.profiles for update using (id = auth.uid()); */\n-- create policy q on public.profiles for update using (id = auth.uid());\n"},
		"not a migration":          {"db/schema.sql": rlsTable + rlsUpdatePolicy},
		"test fixture":             {"test/fixtures/migrations/0001.sql": rlsTable + rlsUpdatePolicy},
		"altered policy":           {"supabase/migrations/0001.sql": rlsTable + rlsUpdatePolicy + "alter policy p on public.profiles using (id = auth.uid() and not is_admin);\n"},
	} {
		if got := rlsHits(t, files); len(got) != 0 {
			t.Errorf("%s: must not fire, got %v", name, got)
		}
	}
}

func TestSplitSQL(t *testing.T) {
	src := "-- c; one\ncreate function f() returns void as $body$ begin perform 1; end $body$ language plpgsql;\n\n/* a; /* nested; */ b */ select 'x;y', \"a;b\"\n  from t;\nselect E'it\\'s;';"
	got := splitSQL(src)
	if len(got) != 3 {
		t.Fatalf("statements = %+v", got)
	}
	if got[0].line != 2 || !strings.HasPrefix(got[0].text, "create function") || got[1].line != 4 || got[2].line != 6 {
		t.Errorf("statements = %+v", got)
	}
}

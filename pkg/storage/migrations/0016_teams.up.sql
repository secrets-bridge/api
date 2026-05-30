-- 0016_teams
--
-- Introduces a first-class team hierarchy so role grants in user_roles
-- can target an entire subtree instead of one project at a time.
--
-- Schema invariants:
--   - parent_team_id self-references teams.id with N-level nesting; root
--     teams have NULL parent. ON DELETE RESTRICT — a team with children
--     must be unparented before it can be removed; this is safer than
--     CASCADE which would silently delete every descendant + its grants.
--   - Name uniqueness is scoped to (parent_team_id, name) so two
--     siblings can never collide. Root teams are gated by a partial
--     unique index over name WHERE parent_team_id IS NULL (Postgres
--     treats NULL as distinct in regular unique indexes).
--   - Membership is structural ONLY. The (role, scope) pair in
--     user_roles still governs WHAT a user can do; a row in team_members
--     just records WHO BELONGS TO WHAT, no implicit grants.
--   - Cycle prevention is enforced at the application layer: the repo's
--     Create / Update rejects a parent_team_id that lives inside the
--     team's own subtree. A CHECK constraint can't express that.
--
-- Companion follow-up migrations (not in this PR):
--   - 0017 will add projects.team_id UUID alongside the legacy
--     owner_team_id TEXT. Once operators backfill, owner_team_id will be
--     dropped.
--   - A future migration introduces a CHECK or trigger that enforces
--     "team must be active before it can hold members" if operators want
--     archival to lock out new membership.

BEGIN;

CREATE TABLE teams (
    id              UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL CHECK (name <> ''),
    parent_team_id  UUID REFERENCES teams (id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'archived')),
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Siblings cannot share a name. Root teams (parent NULL) and child
-- teams need separate unique indexes because Postgres treats NULL as
-- distinct values in a regular unique constraint.
CREATE UNIQUE INDEX teams_name_per_parent_uniq
    ON teams (parent_team_id, name)
    WHERE parent_team_id IS NOT NULL;

CREATE UNIQUE INDEX teams_name_root_uniq
    ON teams (name)
    WHERE parent_team_id IS NULL;

CREATE INDEX teams_parent_team_id_idx
    ON teams (parent_team_id)
    WHERE parent_team_id IS NOT NULL;

CREATE TRIGGER teams_touch_updated_at
    BEFORE UPDATE ON teams
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

CREATE TABLE team_members (
    team_id     UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES local_users (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES local_users (id) ON DELETE SET NULL,
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX team_members_user_id_idx ON team_members (user_id);

COMMIT;

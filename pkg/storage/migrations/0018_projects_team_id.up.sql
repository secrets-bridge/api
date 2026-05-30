-- 0018_projects_team_id
--
-- Wires projects into the team hierarchy added by 0016. A project gains
-- a nullable team_id pointing at the team that owns it. NULL means
-- "unscoped to a team" (back-compat: pre-existing projects keep working
-- until an admin reassigns them).
--
-- The legacy owner_team_id TEXT column from 0001 stays in place for
-- now — operators may have it threaded through external tooling. A
-- future migration drops it once we've confirmed no live install reads
-- it.
--
-- FK action notes:
--   - ON DELETE SET NULL: deleting a team un-scopes any projects it
--     owned rather than cascade-deleting the project rows. Cascade
--     would destroy audit history (audit_events references project_id
--     via the requests path); SET NULL preserves the rows so reports
--     scoped to those projects can still load.
--   - We do NOT mirror the team's archived status onto the project.
--     Archive is independent: a team can be archived while projects
--     under it stay active during a wind-down.

BEGIN;

ALTER TABLE projects
    ADD COLUMN team_id UUID REFERENCES teams (id) ON DELETE SET NULL;

CREATE INDEX projects_team_id_idx
    ON projects (team_id)
    WHERE team_id IS NOT NULL;

COMMIT;

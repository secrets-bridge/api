-- 0039: project and team logos.
--
-- Two new tables, one per entity, so each logo row is tied to its owner
-- by a real foreign key and goes away with it (ON DELETE CASCADE). No
-- existing table changes.
--
-- A logo is not a secret, so it may live in Postgres. The service
-- re-encodes every upload as PNG (dropping metadata) before it gets
-- here, and the CHECK caps the stored image at 64 KiB as a second line
-- behind the service limit. sha256 is the hex digest of the stored
-- PNG; its first 12 characters are the logo_version clients put in the
-- image URL. updated_by is the actor identity (local user UUID or OIDC
-- subject) as TEXT, like the other actor columns.

BEGIN;

CREATE TABLE project_logos (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    png        BYTEA NOT NULL CHECK (octet_length(png) <= 65536),
    sha256     TEXT NOT NULL,
    width      INT NOT NULL,
    height     INT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE team_logos (
    team_id    UUID PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    png        BYTEA NOT NULL CHECK (octet_length(png) <= 65536),
    sha256     TEXT NOT NULL,
    width      INT NOT NULL,
    height     INT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;

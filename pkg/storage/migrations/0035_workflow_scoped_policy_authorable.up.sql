-- R-follow-up #1 (api#118) — adds the scoped policy authoring opt-in
-- flag to workflow_definitions. Default-deny mirrors EPIC Q's
-- self_service_bindable precedent: every existing workflow becomes
-- invisible to scoped policy authors until platform explicitly opts
-- each one in.
--
-- The defensive client-side filter in EPIC R Slice R3 (enabled +
-- non-system) stays in place until R3 is updated in the ui half of
-- this follow-up; both filters are safe-by-additive so a partial
-- rollout doesn't widen the surface.
--
-- Closes the §5 correction 3 gap from the EPIC R design pass.

ALTER TABLE workflow_definitions
    ADD COLUMN scoped_policy_authorable BOOLEAN NOT NULL DEFAULT false;

-- Partial index aligned with the actual dropdown query so a single
-- index seek answers GET /api/v1/workflows/scoped-policy-authorable
-- even with thousands of workflows.
--
-- §1 Q2 correction (locked in design pass): the index keys on (name)
-- with the predicate WHERE enabled=true AND scoped_policy_authorable
-- =true so the planner matches the query verbatim. Indexing the
-- boolean alone would be useless — every indexed row would share the
-- same value.
CREATE INDEX workflow_definitions_scoped_policy_authorable_idx
    ON workflow_definitions (name)
    WHERE enabled = true
      AND scoped_policy_authorable = true;

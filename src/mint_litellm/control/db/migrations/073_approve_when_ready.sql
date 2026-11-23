-- An administrator's approval is kept even when the execution pack is not built yet; it is
-- applied by the job that finishes the pack.
ALTER TABLE mint.intakes ADD COLUMN approve_when_ready jsonb;

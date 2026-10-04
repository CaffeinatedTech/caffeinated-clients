-- 0005_job_notes.sql — attach notes to jobs.
-- A job note is a notes row with job_id set; its client_id is the job's client.
-- It reuses the existing note machinery (title/body, pin, is_secret, audited
-- reveal, search exclusion) rather than inventing a second object. Deleting a
-- job removes its notes (F7.6). Never edit an applied migration; add a new one.

ALTER TABLE notes ADD COLUMN job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE;
CREATE INDEX idx_notes_job ON notes(job_id);

-- Seed for the SQLi playground (#47). Two tables: a `notes` table the api's
-- `/lookup` queries, and a `secrets` table holding a flag that is never served
-- on a benign path. The flag is reachable only by injecting a UNION into the
-- lookup query, so its appearance in an HTTP response is an unambiguous witness
-- that the injection executed.
--
-- The witness value is mirrored by the SQLI_WITNESS constant in the
-- orchestrator's `sqli_playground_is_exploitable` test; keep the two in sync.

CREATE TABLE notes (
    label text PRIMARY KEY,
    body  text NOT NULL
);

CREATE TABLE secrets (
    flag text NOT NULL
);

INSERT INTO notes (label, body) VALUES
    ('welcome', 'hello from the api'),
    ('status',  'all systems nominal');

INSERT INTO secrets (flag) VALUES ('REDSTEP_SQLI_WITNESS_7F3A');

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

-- A per-user object table for the IDOR playground (#64). `/object?id=` serves a
-- row by id; the vulnerable build omits the ownership check, so one user reads
-- another's object. bob's body is a bob-only value that is never served on
-- alice's own object, so its appearance in a response alice made is an
-- unambiguous witness that she read across the ownership boundary. The witness is
-- mirrored by the IDOR_WITNESS constant in the orchestrator's cross-check test;
-- keep the two in sync.
CREATE TABLE objects (
    id    int  PRIMARY KEY,
    owner text NOT NULL,
    body  text NOT NULL
);

INSERT INTO objects (id, owner, body) VALUES
    (1, 'alice', 'alice private note'),
    (2, 'bob',   'REDSTEP_IDOR_WITNESS_9C2E');

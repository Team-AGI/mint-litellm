-- Store observed delivery stages for each decision version and target.
CREATE TABLE mint.delivery_receipts (
    instance_id mint.ident NOT NULL,
    intake_id uuid NOT NULL REFERENCES mint.intakes(id),
    decision_version bigint NOT NULL CHECK (decision_version > 0),
    stage text NOT NULL CHECK (stage IN ('approved', 'registry_active', 'key_applied',
        'device_received', 'started', 'discovered', 'first_response')),
    target text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, intake_id, decision_version, stage, target)
);
REVOKE ALL ON mint.delivery_receipts FROM PUBLIC;
GRANT SELECT, INSERT ON mint.delivery_receipts TO mint_control, mint_worker;

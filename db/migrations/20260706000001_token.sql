create table if not exists token
(
    slot_id       integer primary key not null,
    label         text,
    so_pin_hash   text                not null,
    user_pin_hash text
);

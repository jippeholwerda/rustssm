create table if not exists object
(
    id            integer primary key autoincrement not null,
    content       blob                              not null,
    private       integer                           not null,
    label         text,
    -- Null for token objects (persistent); otherwise the id of the session
    -- that owns this session object (destroyed when that session closes).
    owner_session integer
);

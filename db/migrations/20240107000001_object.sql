-- Token objects only: session objects (CKA_TOKEN false) live in process
-- memory and never reach the store. `autoincrement` keeps rowids (= object
-- handles) monotonic and never reused; it also keeps bit 63 clear, which the
-- in-memory store uses to mark its handles.
create table if not exists object
(
    id      integer primary key autoincrement not null,
    content blob                              not null,
    private integer                           not null,
    label   text
);

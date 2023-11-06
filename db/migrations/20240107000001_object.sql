create table if not exists object
(
    id integer primary key autoincrement not null,
    content blob not null,
    private integer not null,
    label text
);

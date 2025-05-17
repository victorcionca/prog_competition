create table users(
    email text,
    salt blob,
    password text,
    name text,
    id text,
    container_id text,
    score real,
    verified int,
    medsuccess int);

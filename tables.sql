CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    profile_pic_path TEXT DEFAULT 'static/img/profilepic.png',
    -- 1 GB (1024 MB)
    free_space REAL NOT NULL DEFAULT (1024 * 1024 * 1024)
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    subject INTEGER NOT NULL,
    content TEXT NOT NULL,
    date TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,

    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS emails_sent (
    email_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    favorite INTEGER NOT NULL,

    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS emails_received (
    email_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    favorite INTEGER NOT NULL,

    FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    email_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    type TEXT NOT NULL,
    size REAL NOT NULL,
    CONSTRAINT fk_email_id
        FOREIGN KEY (email_id)
        REFERENCES emails(id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX email ON users (email);
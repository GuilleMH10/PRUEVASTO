const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./database.db");

db.serialize(()=>{

    db.run(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            date TEXT,
            status TEXT,
            user_id INTEGER
        )
    `);

});
db.run(`
CREATE TABLE IF NOT EXISTS password_resets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    token TEXT,
    expires INTEGER
)
`);
module.exports = db;

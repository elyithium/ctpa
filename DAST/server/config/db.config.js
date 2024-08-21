// server/config/config.js
module.exports = {
    development: {
        username: "your_username",
        password: "your_password",
        database: "dast_database",
        host: "127.0.0.1",
        dialect: "postgres" // Or 'mysql' depending on your database
    },
    production: {
        username: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        host: process.env.DB_HOST,
        dialect: "postgres" // Or 'mysql' depending on your database
    }
};

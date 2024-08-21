// server/models/index.js

const mongoose = require('mongoose');

// Import your models
const Report = require('./report.model');

const db = {
    Report,
    mongoose
};

// Export the db object containing all your models
module.exports = db;

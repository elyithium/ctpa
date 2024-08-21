// server/server.js

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const scanRoutes = require('./routes/scanRoutes');
const reportRoutes = require('./routes/reportRoutes');

const app = express();

// Enable CORS for all routes, allowing requests from http://localhost:3000
app.use(cors({
    origin: 'http://localhost:3000', // Allow requests from this origin
    methods: 'GET,POST', // Allow specific HTTP methods
    allowedHeaders: 'Content-Type,Authorization', // Allow specific headers
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, '../../client/build')));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/dast', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
    console.log('Connected to the MongoDB database');
});

// API routes
app.use('/api', scanRoutes);
app.use('/api/reports', reportRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Default endpoint to check if the server is running
app.get('/', (req, res) => res.send('Hello from the backend!'));

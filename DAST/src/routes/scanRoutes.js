// src/routes/scanRoutes.js
const express = require('express');
const ScanController = require('../controllers/ScanController');
const router = express.Router();

router.post('/scan', ScanController.startScan);

module.exports = router;

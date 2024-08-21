const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/ReportController');

// Route to get a report by ID
router.get('/:id', async (req, res) => {
    try {
        const report = await ReportController.getReportById(req.params.id);
        if (!report) {
            return res.status(404).json({ message: 'Report not found' });
        }
        res.json(report);
    } catch (error) {
        console.error('Error fetching report:', error);
        res.status(500).json({ message: 'Failed to retrieve report' });
    }
});

// Additional routes for managing reports (e.g., create, delete, list all)
module.exports = router;

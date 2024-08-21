const ReportController = require('./ReportController');
const SQLInjectionScanner = require('../scanners/SQLInjectionScanner');

class ScanController {
    static async startScan(req, res) {
        const { target } = req.body;
        try {
            // Run your SQL Injection scanner or other scanners
            const sqlInjectionScanner = new SQLInjectionScanner();
            const sqlInjectionResults = await sqlInjectionScanner.startScan(target);

            // Create and save the report using ReportController
            const report = await ReportController.createReport(target, sqlInjectionResults);

            // Send the report back to the frontend
            res.json({ report });

        } catch (error) {
            console.error('Scan failed:', error);
            res.status(500).json({ error: 'An error occurred during the scan.' });
        }
    }
}

module.exports = ScanController;

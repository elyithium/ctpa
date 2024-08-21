const Report = require('../models/report.model');

class ReportController {
    // Method to create and save a new report
    static async createReport(target, scanResults) {
        try {
            // Create and save the report with embedded vulnerabilities
            const report = new Report({
                target,
                vulnerabilities: scanResults, // Directly embed vulnerabilities
            });

            await report.save();

            return report;
        } catch (error) {
            console.error('Error creating report:', error);
            throw new Error('Failed to create report.');
        }
    }

    // Method to retrieve a report by ID
    static async getReportById(reportId) {
        try {
            const report = await Report.findById(reportId).exec();
            return report;
        } catch (error) {
            console.error('Error fetching report:', error);
            throw new Error('Failed to retrieve report.');
        }
    }

    // Method to retrieve all reports
    static async getAllReports() {
        try {
            const reports = await Report.find().exec();
            return reports;
        } catch (error) {
            console.error('Error fetching reports:', error);
            throw new Error('Failed to retrieve reports.');
        }
    }
}

module.exports = ReportController;

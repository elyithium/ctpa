// src/controllers/ScanController.js
const { XSSScanner, SQLInjectionScanner, CSRFScanner } = require('../scanners');

class ScanController {
	static async startScan(req, res) {
		const target = req.body.target;
		const xssScanner = new XSSScanner();
		const sqlInjectionScanner = new SQLInjectionScanner();
		const csrfScanner = new CSRFScanner();

		const xssResult = xssScanner.startScan(target);
		const sqlResult = sqlInjectionScanner.startScan(target);
		const csrfResult = csrfScanner.startScan(target);

		res.json({
			target,
			results: {
				xss: xssResult,
				sqlInjection: sqlResult,
				csrf: csrfResult
			}
		});
	}
}

module.exports = ScanController;

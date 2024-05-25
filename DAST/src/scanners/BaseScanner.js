// src/scanners/BaseScanner.js
class BaseScanner {
	constructor(name) {
		this.name = name;
	}

	startScan(target) {
		throw new Error("startScan method must be implemented by subclasses");
	}

	logResult(result) {
		console.log(`${this.name} Scanner: ${result}`);
	}
}

module.exports = BaseScanner;

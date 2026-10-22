const assert = require('node:assert/strict');
const test = require('node:test');
const { SYSTEM_PROMPT } = require('../src/prompt');

test('chat guidance includes the supplied official portal purposes and destinations', () => {
  for (const value of [
    'GRM (Grievance Redressal Mechanism)',
    'direct the user to contact their respective bank',
    'Do not give steps for applying through GRM.',
    'MRM (Money Restoration Portal / Money Restoration Module)',
    'launched by the Ministry of Home Affairs through I4C',
    'recover frozen funds digitally',
    'contact the respective cyber police station handling their case for complaint updates',
    'Do not give application steps or imply approval is guaranteed.',
    'subject to verification and approval',
    'NCRP (National Cyber Crime Reporting Portal)',
    'CEIR',
    'TAFCOP',
    'Chakshu',
    'KYM (Know Your Mobile)',
    'Report Suspect',
    'CFCFRMS (Citizen Financial Cyber Fraud Reporting and Management System)',
    'DIP (Digital Intelligence Platform)',
    'It is not a public citizen portal.',
    'RICWIN',
    'KYI (Know Your Internet Service Provider)',
    'CERT-In',
    'Cyber Swachhta Kendra',
    'CPGRAMS',
    'https://pgportal.gov.in/',
  ]) {
    assert.ok(SYSTEM_PROMPT.includes(value), `Expected portal guidance to include "${value}"`);
  }
});

test('does not expose GRM or MRM as service cards', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const services = fs.readFileSync(path.join(__dirname, '../../Bot/src/data/services.ts'), 'utf8');
  assert.doesNotMatch(services, /id: '(?:grm|mrm)'/);
});

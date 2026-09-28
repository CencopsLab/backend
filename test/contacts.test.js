const assert = require('node:assert/strict');
const test = require('node:test');
const contacts = require('../data/contacts.json');

test('backend contact directory includes DSP, SHO, and public helplines', () => {
  assert.deepEqual(
    contacts.map(({ id }) => id),
    ['dsp-cyber', 'sho-cyber', 'cyber-helpline', 'emergency'],
  );

  const dsp = contacts.find(({ id }) => id === 'dsp-cyber');
  const sho = contacts.find(({ id }) => id === 'sho-cyber');
  assert.equal(dsp.name, 'DSP Cyber, Chandigarh Police');
  assert.equal(sho.name, 'SHO Cyber, Chandigarh Police');
  assert.equal(contacts.find(({ id }) => id === 'cyber-helpline').phone, '1930');
  assert.equal(contacts.find(({ id }) => id === 'emergency').phone, '112');
});
const assert = require('assert');
const A = require('../analyzer.js');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ok ${name}`); passed++; }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); failed++; }
}

test('placeholder', () => { assert.ok(true); });

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

//import * as assert from 'assert';
import * as crypto from 'crypto';

describe('crypto', () => {
	it('getHashes()', async () => {
		console.log(JSON.stringify(crypto.getHashes()));
	});

	it('getCurves()', async () => {
		console.log(JSON.stringify(crypto.getCurves()));
	});
});

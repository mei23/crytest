//import * as assert from 'assert';
import * as crypto from 'crypto';
import { inspect } from 'util';

describe('crypto', () => {
	it('getHashes()', async () => {
		console.log(inspect(crypto.getHashes()));
	});

	it('getCurves()', async () => {
		console.log(inspect(crypto.getCurves()));
	});
});

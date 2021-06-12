import * as assert from 'assert';
import { HttpSignature } from '../src/utils/http-signature';
import { genRsaKeyPair, genEcKeyPair } from '../src/utils/keypair';
import * as httpSignature from 'http-signature';

type ParsedSignature = {
	scheme: 'Signature';
	params: {
		keyId: string;
		algorithm: string;	// 'rsa-sha256'
		headers: string[];	//[ '(request-target)', 'date', 'host', 'digest' ],
		signature: string;
	};
	signingString: string;
	algorithm: string;	// 'RSA-SHA256'
	keyId: string;
};

const buildParsedSignature = (signingString: string, signature: string, algorithm: string) => {
	return {
		scheme: 'Signature',
		params: {
			keyId: 'KeyID',
			algorithm: algorithm,
			headers: [ '(request-target)', 'date', 'host', 'digest' ],
			signature: signature,
		},
		signingString: signingString,
		algorithm: algorithm.toUpperCase(),
		keyId: 'KeyID',
	} as ParsedSignature;
};

describe('HTTP Signature verify by joyent', () => {
	it('rsa-sha1 1024', async () => {
		const keyPair = await genRsaKeyPair(1024);
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha1');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha1');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('rsa-sha256 4096', async () => {
		const keyPair = await genRsaKeyPair(4096);
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha256');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});
	it('rsa-sha512 4096', async () => {
		const keyPair = await genRsaKeyPair(4096);
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'rsa-sha512');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('ecdsa-sha256 prime256v1', async () => {
		const keyPair = await genEcKeyPair('prime256v1');
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha256');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha256');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});

	it('ecdsa-sha512 secp521r1', async () => {
		const keyPair = await genEcKeyPair('secp521r1');
		const signingString = 'foo';
		const signature = HttpSignature.genSignature(signingString, keyPair.privateKey, 'sha512');
		const parsed = buildParsedSignature(signingString, signature, 'ecdsa-sha512');
		const result = httpSignature.verifySignature(parsed, keyPair.publicKey);
		assert.deepStrictEqual(result, true);
	});
});

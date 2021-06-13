import { inspect } from 'util';
import { genSignature, genSignatureHeader, genSigningString, RequestOptions, signToRequest } from './http-signature';
import { genEd448KeyPair, genRsaKeyPair } from './keypair';

async function main() {
	const keypair = await genRsaKeyPair();

	const requestOptions: RequestOptions = {
		url: 'https://host2.test/inbox',
		method: 'POST',
		headers: {
			host: 'host2.test',
			date: new Date().toUTCString(),
			digest: 'x',
		}
	};

	const includeHeaders = ['(request-target)', 'host', 'date', 'digest'];
	const signingString = genSigningString(requestOptions, includeHeaders);

	const signature = genSignature(signingString, keypair.privateKey, 'sha256');
	//const authorizationHeader = genAuthorizationHeader(includeHeaders, 'x1', signature);
	const signatureHeader = genSignatureHeader(includeHeaders, 'x1', signature, 'rsa-sha256');

	console.log(inspect({
		privateKey: keypair.privateKey,
		publicKey: keypair.publicKey,
		signingString,
		signature,
		signatureHeader,
	}));

	const kp = await genEd448KeyPair();

	const re = signToRequest(requestOptions, includeHeaders, { privateKeyPem: kp.privateKey, keyId: 'key1' });
	console.log(inspect(requestOptions));
	console.log(inspect(re));
}

main()
	.then(() => {})
	.catch(e => console.log(e));

import { inspect } from 'util';
import { RequestOptions, HttpSignature } from './utils/http-signature';
import { genRsaKeyPair } from './utils/keypair';

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
	const signingString = HttpSignature.genSigningString(requestOptions, includeHeaders);

	const signature = HttpSignature.genSignature(signingString, keypair.privateKey);
	//const authorizationHeader = genAuthorizationHeader(includeHeaders, 'x1', signature);
	const signatureHeader = HttpSignature.genSignatureHeader(includeHeaders, 'x1', signature);

	console.log(inspect({
		privateKey: keypair.privateKey,
		publicKey: keypair.publicKey,
		signingString,
		signature,
		signatureHeader,
	}));

	const sn = new HttpSignature({ privateKeyPem: keypair.privateKey, keyId: 'key1' });
	const re = sn.signToRequest(requestOptions, includeHeaders);
	console.log(inspect(requestOptions));
	console.log(inspect(re));
}

main()
	.then(() => {})
	.catch(e => console.log(e));

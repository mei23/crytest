import { inspect } from 'util';
import { HttpRequestOptions, genSigningString, genSignature, genSignatureHeader } from './utils/http-signature';
import { genRsaKeyPair } from './utils/keypair';

async function main() {
	const keypair = await genRsaKeyPair();

	const requestOptions: HttpRequestOptions = {
		url: 'https://host2.test/inbox',
		method: 'POST',
		headers: {
			host: 'host2.test',
			date: new Date().toUTCString(),
			digest: 'x',
		}
	};

	const includeHeaders = ['(request-target)', 'host', 'date', 'digest'];
	const signingString = genSigningString(includeHeaders, requestOptions);

	const signature = genSignature(signingString, keypair.privateKey);
	//const authorizationHeader = genAuthorizationHeader(includeHeaders, 'x1', signature);
	const signatureHeader = genSignatureHeader(includeHeaders, 'x1', signature);

	console.log(inspect({
		privateKey: keypair.privateKey,
		publicKey: keypair.publicKey,
		signingString,
		signature,
		signatureHeader,
	}));
}

main()
	.then(() => {})
	.catch(e => console.log(e));

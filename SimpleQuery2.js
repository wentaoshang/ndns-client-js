var DnsParser = require('./DnsParser.js').DnsParser;
var ndn = require('ndn-on-node');
var policy = require('./policy/IdentityPolicy').NdnsPolicy;
var VerifyResult = require('./policy/IdentityPolicy').VerifyResult;

if (process.argv.length != 3)
    throw new Error('must specify an NDNS name as a command-line parameter.');

var onData = function (inst, co) {
    console.log('Data name: ' + co.name.to_uri());
    console.log('Content: \n' + co.to_xml());

    policy.verify(co, function (result) {
	    if (result == VerifyResult.SUCCESS) {
		var parser = new DnsParser(co.content);
		
		try {
		    var packet = parser.parse();
		    
		    console.log(require('util').inspect(packet, {depth: 5}));
		    console.log(parser.buffer.endOfBuffer());
		} catch (e) {
		    // Content is not a DNS packet.
		    console.log(e.message);
		    console.log('not a DNS packet.');
		}
	    } else if (result == VerifyResult.FAILURE)
		console.log('Verification failed.');
	    else if (result == VerifyResult.TIMEOUT)
		console.log('Verification failed due to timeout.');

	    ndnHandle.close();
	});
};

var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.to_uri());
    ndnHandle.close();
};

var ndnHandle = new ndn.NDN();

ndnHandle.onopen = function () {
    var n = new ndn.Name(process.argv[2]);
    var template = new ndn.Interest();
    template.interestLifetime = 4000;
    ndnHandle.expressInterest(n, template, onData, onTimeout);
};

ndnHandle.connect();

console.log('Started...');

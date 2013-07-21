var DnsParser = require('./DnsParser.js').DnsParser;
var ndn = require('ndn-on-node');

if (process.argv.length != 3)
    throw new Error('must specify an NDNS name as a command-line parameter.');

var dataStack = [];  // stack to hold unverified content object

var onData = function (inst, co) {
    console.log('Data name: ' + co.name.to_uri());

    var parser = new DnsParser(co.content);

    try {
	var packet = parser.parse();
	
	console.log(packet);
	console.log(packet.answer[0].rdata);
	console.log(parser.buffer.endOfBuffer());
    } catch (e) {
	// Content is not a DNS packet.
	console.log('not a DNS packet.')
    }
    
    var loc = co.signedInfo.locator;
    if (loc.type == ndn.KeyLocatorType.KEYNAME) {
	dataStack.push(co);
	var n = loc.keyName.name;
	var template = new ndn.Interest();
	template.answerOriginKind = ndn.Interest.ANSWER_NO_CONTENT_STORE;  // bypass cache in ccnd
	template.interestLifetime = 4000;
	ndnHandle.expressInterest(n, template, onData, onTimeout);
    } else if (loc.type == ndn.KeyLocatorType.KEY) {
	console.log('Root key received.');
	var result = false;
	var i;
	var keyData = co;
	for (i = dataStack.length - 1; i >= 0; i--) {
	    var data = dataStack[i];
	    var key = new ndn.Key();
	    key.readDerPublicKey(keyData.content);
	    result = data.verify(key);
	    if (result == false)
		break;
	    keyData = data;
	}
	
	if (result)
	    console.log('Data verified for content name ' + dataStack[0].name.to_uri());
	else
	    console.log('Data verification failed for content name ' + dataStack[i].name.to_uri());

	ndnHandle.close();
    } else {
	console.log('KeyLocator type is ' + loc.type);
	ndnHandle.close();  // This will cause the script to quit
    }
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

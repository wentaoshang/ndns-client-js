var DnsParser = require('./DnsParser.js').DnsParser;
var ndn = require('ndn-on-node');

var onData = function (inst, co) {
    console.log("ContentObject received in callback.");
    console.log('Name: ' + co.name.to_uri());

    var parser = new DnsParser(co.content);

    var packet = parser.parse();

    console.log(packet);
    console.log(packet.answer[0].rdata);
    
    ndnHandle.close();  // This will cause the script to quit
};

var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.to_uri());
    ndnHandle.close();
};

var ndnHandle = new ndn.NDN();

ndnHandle.onopen = function () {
    var n = new ndn.Name('/ndn/ucla.edu/DNS/NS');
    var template = new ndn.Interest();
    template.answerOriginKind = ndn.Interest.ANSWER_NO_CONTENT_STORE;  // bypass cache in ccnd
    template.interestLifetime = 4000;
    ndnHandle.expressInterest(n, template, onData, onTimeout);
    console.log('Interest expressed.');
};

ndnHandle.connect();

console.log('Started...');

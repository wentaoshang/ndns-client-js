var DnsParser = require('./DnsParser.js').DnsParser;
var RRType = require('./DnsParser.js').RRType;
var ndn = require('ndn-on-node');
var policy = require('./policy/IdentityPolicy').NdnsPolicy;
var VerifyResult = require('./policy/IdentityPolicy').VerifyResult;

if (process.argv.length != 3)
    throw new Error('must specify an NDNS name as a command-line parameter.');


var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.to_uri());
    handle.close();
};


// Convert DNS name string to NDN Name object.
var ndnify = function (str) {
    var arr = str.split('.');
    var n = new ndn.Name();
    for (var i = arr.length - 1; i >= 0; i--) {
	if (arr[i].length == 0)
	    continue;
	
	n.append(arr[i]);
    }
    return n;
};

// Convert NDN Name object to DNS name string.
var dnsify = function (name) {
    var str = '';
    for (var i = 0; i < name.size(); i++) {
	str += ndn.Name.toEscapedString(name.components[i]) + '.';
    }
    return str;
};

// 'Relativize' dname against zone.
var relativize = function (dname, zone) {
    if (zone == null || zone.length == 0 || zone == '.')
	return dname;

    var zpos = dname.length - zone.length;
    if (dname.substr(zpos) == zone)
	return dname.substr(0, zpos);
    else
	return dname;
};

// 'hint' and 'zone' are NDN Name objects while 'lable' and 'rrtype' are strings.
var generateQuestion = function (hint, zone, lable, rrtype) {
    var q = new ndn.Name();
    q.append(zone).append('DNS');

    if (lable != null)
	q.append(ndnify(lable));
    
    if (rrtype != null)
	q.append(rrtype);

    if (hint != null && hint.size() > 0 && !hint.isPrefixOf(q)) {
	q = new ndn.Name().append(hint).append('%F0.').append(q);;
    }

    return q;
};

var handle = new ndn.NDN();

handle.onopen = function () {
    var question = (process.argv[2]).split('/').slice(1);
    var iter = 0;
    var rrtype = 'NS';
    var zone = new ndn.Name();
    var hint = new ndn.Name();
    var lastq = false;

    var onData = function (inst, co) {
	console.log('Data name: ' + co.name.to_uri());
	//console.log('Content: \n' + co.to_xml());
	
    policy.verify(co, function (result) {
	    if (result == VerifyResult.FAILURE) {
		console.log('Verification failed.');
		return;
	    } else if (result == VerifyResult.TIMEOUT) {
		console.log('Verification failed due to timeout.');
		return;
	    }
	    
	    if (lastq) {
		console.log('Result found.');
		handle.close();
		return;
	    }


	    var parser = new DnsParser(co.content);
	
	    try {
		var packet = parser.parse();
	    
		//console.log(require('util').inspect(packet, {depth: 5}));
		//console.log(parser.buffer.endOfBuffer());

		if (rrtype == 'NS' && packet.answer.length > 0 && packet.answer[0].type == RRType.NS) {
		    var target = packet.answer[0].rdata.nsdname;
		    target = relativize(target, dnsify(zone));
		    rrtype = 'FH';
		    var qfh = generateQuestion(hint, zone, target, rrtype);
		    handle.expressInterest(qfh, null, onData, onTimeout);
		} else if (rrtype == 'NS' && packet.answer.length > 0 && packet.answer[0].type == RRType.NEXISTS) {
		    console.log('NS does not exist.');
		    rrtype = question[question.length - 1];
		    var last = generateQuestion(hint, zone);
		    for (var i = iter; i < question.length; i++) {
			last.append(question[i]);
		    }
		    lastq = true;
		    handle.expressInterest(last, null, onData, onTimeout);
		} else if (rrtype == 'FH' && packet.answer.length > 0 && packet.answer[0].type == RRType.FH) {
		    hint = packet.answer[0].rdata.hint;
		    rrtype = 'NS';
		    zone.append(question[iter++]);
		    var qns = generateQuestion(hint, zone, question[iter], rrtype);
		    handle.expressInterest(qns, null, onData, onTimeout);
		}
	    } catch (e) {
		// Content is not a DNS packet.
		console.log(e.message);
		console.log('not a DNS packet.');
		handle.close();
	    }
	});
    };

    var q = generateQuestion(hint, zone, question[iter], rrtype);
    handle.expressInterest(q, null, onData, onTimeout);
};

handle.connect();

var ndn = require('ndn-on-node');

var IdentityPolicy = function IdentityPolicy(anchors, rules, chain_limit) {
    this.anchors = anchors != null ? anchors : [];
    this.rules = rules != null ? rules : [];
    this.chain_limit = chain_limit != null ? chain_limit : 10;
};

exports.IdentityPolicy = IdentityPolicy;

var VerifyResult = {
SUCCESS: 1,
FAILURE: 2,
TIMEOUT: 3  // Timeout when fetching the key chain
};

exports.VerifyResult = VerifyResult;

/**
 * Recursive verification closure
 * @param {ContentObject} data The parsed ContentObject to be verified
 * @param {Function} callback The callback function that is called when the verification process finishes.
 *  The prototype for this callback is function (result) {}, where 'result' is a flag indicating the verification result.
 */
IdentityPolicy.prototype.verify = function (data, callback) {
    if (this.anchors.length == 0)
	return false;
    
    var dataStack = [];  // stack to hold unverified content object

    var self = this;

    var chain_length = 0;

    var verifyStack = function (/*Key*/ rootKey) {
	var result;
	var i;
	var key = rootKey;
	for (i = dataStack.length - 1; i >= 0; i--) {
	    var d = dataStack[i];
	    result = d.verify(key);
	    if (result == false)
		break;
	    key = new ndn.Key();
	    key.readDerPublicKey(d.content);
	}
	
	if (result == true) {
	    console.log('Signature verified for content name ' + dataStack[0].name.to_uri());
	    callback(VerifyResult.SUCCESS);
	} else {
	    console.log('Signature verification failed for content name ' + dataStack[i].name.to_uri());
	    console.log('Using public key: \n' + key.publicToDER().toString('hex'));
	    callback(VerifyResult.FAILURE);
	}
    };

    var onData = function (inst, co) {
	chain_length++;
	if (chain_length > self.chain_limit) {
	    console.log('Abort identity verification due to over-limit chain length.');
	    callback(VerifyResult.FAILURE);  // TODO: add a new status flag for this type of failure
	}

	var loc = co.signedInfo.locator;
	if (loc.type == ndn.KeyLocatorType.KEYNAME) {
	    var keyName = loc.keyName.name;
	    console.log('Checking key name: ' + keyName.to_uri());
	    // Check policy
	    var anchorKey = self.authorize_by_anchors(co.name, keyName);
	    if (anchorKey != null) {
		dataStack.push(co);
		verifyStack(anchorKey);
		handle.close();
		return;
	    }

	    if (self.authorize_by_rules(co.name, keyName) == false) {
		console.log('Verification suspended because policy rule checking failed.');
		//callback(VerifyResult.FAILURE);
		return;
	    }

	    // Rule checking passed. Go to fetch the key data.
	    dataStack.push(co);
	    var template = new ndn.Interest();
	    template.answerOriginKind = ndn.Interest.ANSWER_NO_CONTENT_STORE;  // bypass cache in ccnd
	    template.interestLifetime = 4000;
	    handle.expressInterest(keyName, template, onData, onTimeout);
	} else if (loc.type == ndn.KeyLocatorType.KEY) {
	    console.log('Root key received.');
	    var rootKey = new ndn.Key();
	    rootKey.readDerPublicKey(co.content);
	    verifyStack(rootKey);
	    handle.close();
	} else {
	    // This should not happen.
	    console.log('KeyLocator type is ' + loc.type);
	    handle.close();  // This will cause the script to quit
	}
    };

    var onTimeout = function (interest) {
	console.log("Interest time out.");
	console.log('Interest name: ' + interest.name.to_uri());
	callback(VeriftResult.TIMEOUT);
	handle.close();
    };

    var handle = new ndn.NDN();

    handle.onopen = function () {
	// Call onData directly to do policy checking on the 'data' to be verified
	onData(null, data);
    };

    handle.connect();
};

IdentityPolicy.prototype.authorize_by_anchors = function (/*Name*/ dataName, /*Name*/ keyName) {
    for (var i = 0; i < this.anchors.length; i++) {
	if (keyName.to_uri() == this.anchors[i].key_name.to_uri()) {
	    var nsp = this.anchors[i].namespace;
	    if (nsp.isPrefixOf(dataName))
		return this.anchors[i].key;
	}
    }
    return null;
};

IdentityPolicy.prototype.authorize_by_rules = function (/*Name*/ dataName, /*Name*/ keyName) {
    var data_name = dataName.to_uri();
    var key_name = keyName.to_uri();

    for (var i = 0; i < this.rules.length; i++) {
	var rule = this.rules[i];
	if (rule.key_pat.test(key_name) && rule.data_pat.test(data_name)) {
	    var namespace_key = new ndn.Name(key_name.replace(rule.key_pat, rule.key_pat_ext));
	    var namespace_data = new ndn.Name(data_name.replace(rule.data_pat, rule.data_pat_ext));
	    if (namespace_key.isPrefixOf(namespace_data)) {
		console.log('namespace_key: ' + namespace_key.to_uri());
		console.log('namespace_data: ' + namespace_data.to_uri());
		return true;
	    }
	}
    }
    
    return false;
};

var NdnsPolicy = new IdentityPolicy(
    // anchors
    [
{ key_name: new ndn.Name("/ndn/keys/ucla.edu/alex/%C1.M.K%00F%8D%E9%C3%EE4%7F%C1Mjqro%C6L%8DGV%91%90%03%24%ECt%95n%F3%9E%A6i%F1%C9"), 
  namespace: new ndn.Name("/"),
  key: ndn.Key.createFromPEM({ pub: "-----BEGIN PUBLIC KEY-----\n" +
			       "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSPdPM7+DjDcUGHtwEDmkq4kO5\n" +
			       "tEUI05w5gR4JC1UiZxS0ckMWSLRPWXozHrpJsjNzDeI6OiQrXzup1tF2IN+Xtdr+\n" +
			       "Pr3CwyBRloTJJbm5kf+pGuJh4fE9Qk0i/fS9Xs6gFup3oPnr+wFFjJObnRTrUsaM\n" +
			       "8TQokOLYZFsatsZOvwIDAQAB\n" +
			       "-----END PUBLIC KEY-----" }) }
	],
    // rules
    [
{ key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"), 
  key_pat_ext: "$1$2", 
  data_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)$"), 
  data_pat_ext: "$1$2" },
  
{ key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"), 
  key_pat_ext: "$1$2",
  data_pat: new RegExp("^((?:/[^/]+)*)/([^/\.]+)\.([^/\.]+)/DNS((?:/[^/]+)*)$"), 
  data_pat_ext: "$1/$3/$2$4" },

{ key_pat: new RegExp("^((?:/[^/]+)*)/DNS((?:/[^/]+)*)/[^/]+/NDNCERT$"), 
  key_pat_ext: "$1$2", 
  data_pat: /(.*)/, 
  data_pat_ext: "$1" }
	]
    );

exports.NdnsPolicy = NdnsPolicy;

var ndn = require('ndn-on-node');
var BufferIterator = require('./utils/BufferIterator.js').BufferIterator;

var DnsPacket = function DnsPacket () {
    this.header = {
    id: 0,
    qr: 0,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 1,
    ra: 0,
    res1: 0,
    res2: 0,
    res3: 0,
    rcode: 0,
    qdcount: 0,
    ancount: 0,
    nscount: 0,
    arcount: 0
    };
    this.question = null;
    this.answer = null;
    this.authority = null;
    this.additional = null;
};

exports.DnsPacket = DnsPacket;

var DnsParser = function (/*Buffer*/ pkt) {
    this.buffer = new BufferIterator(pkt);
    this.packet = new DnsPacket();
    this.pointerStack = [];  // stack to keep track of previous positions before pointer jumping
};

exports.DnsParser = DnsParser;

DnsParser.prototype.parseHeader = function () {
    // Read header
    this.packet.header.id = this.buffer.readBytesAsNumber(2);
    var flags = this.buffer.readBytesAsNumber(2);
    this.packet.header.qr = (flags & 0x8000) >> 15;
    this.packet.header.opcode = (flags & 0x7800) >> 11;
    this.packet.header.aa = (flags & 0x400) >> 10;
    this.packet.header.tc = (flags & 0x200) >> 9;
    this.packet.header.rd = (flags & 0x100) >> 8;
    this.packet.header.ra = (flags & 0x80) >> 7;
    this.packet.header.rcode = (flags & 0xF);
    this.packet.header.qdcount = this.buffer.readBytesAsNumber(2);
    this.packet.header.ancount = this.buffer.readBytesAsNumber(2);
    this.packet.header.nscount = this.buffer.readBytesAsNumber(2);
    this.packet.header.arcount = this.buffer.readBytesAsNumber(2);

    // Init section holders
    this.packet.question = [];
    this.packet.answer = [];
    this.packet.authority = [];
    this.packet.additional = [];
};

var POINTER_MASK = 0xC0;  // b'11000000'
var OFFSET_MASK = 0x3F;  // b'00111111'
var POINTER_STACK_THRESHOLD = 10;

var isPointer = function (len) {
    return (len & POINTER_MASK) === POINTER_MASK;
};

// Parse domain name lable into a string
DnsParser.prototype.parseLable = function () {
    var len = this.buffer.readBytesAsNumber(1);
    return this.buffer.readBytesAsString(len);
};


// Parse domain name into a string
DnsParser.prototype.parseDomainName = function () {
    var name = "";
    while (this.buffer.peek() != 0) {  // Domain name ends with a zero-byte
	var len = this.buffer.peek();
	if (isPointer(len)) {
	    var off = (this.buffer.readBytesAsNumber(2)) & OFFSET_MASK;
	    if (off >= this.buffer.length)
		throw new Error('Mal-formated domain name pointer. Offset out of range.');
	    if (this.pointerStack.length > POINTER_STACK_THRESHOLD)
		throw new Error('Too many level of pointers.');
	    this.pointerStack.push(this.buffer.offset);  // save current offset
	    this.buffer.seek(off);  // pointer jump
	    name += this.parseDomainName();  // parse domain name at that position until we reach zero-bytes
	    var old_off = this.pointerStack.pop();
	    this.buffer.seek(old_off);  // recover offset
	    return name;  // we are done with this name. There is no zero-byte after the pointer
	} else {
	    name += this.parseLable() + '.';
	}
    }

    // Read ending byte
    this.buffer.advance(1);
    return name;
};

DnsParser.prototype.parseQuestion = function () {
    var obj = new Object();
    obj.qname = this.parseDomainName();  // string
    obj.qtype = this.buffer.readBytesAsNumber(2);
    obj.qclass = this.buffer.readBytesAsNumber(2);
    return obj;
};


var RR_CLASS_IN = 1;

// These are from the DNS standards
var RR_TYPE_NS = 2;
var RR_TYPE_SOA = 6;

// These are defined by ndns
var RR_TYPE_FH = 65429;
var RR_TYPE_NEXISTS = 65430;
var RR_TYPE_NDNCERT = 65431;
var RR_TYPE_NDNCERTSEQ = 65432;
var RR_TYPE_NDNAUTH = 65433;

DnsParser.prototype.parseRData = function (type, clss, rdlength) {
    if (clss != RR_CLASS_IN)
	throw new Error("Unknown DNS RR class: " + clss);

    switch (type) {
    case RR_TYPE_NS:
	var obj = new Object();
	obj.nsdname = this.parseDomainName();
	return obj;
    case RR_TYPE_SOA:
	var obj = new Object();
	obj.mname = this.parseDomainName();
	obj.rname = this.parseDomainName();
	obj.serial = this.buffer.readBytesAsNumber(4);
	obj.refresh = this.buffer.readBytesAsNumber(4);
	obj.retry = this.buffer.readBytesAsNumber(4);
	obj.expire = this.buffer.readBytesAsNumber(4);
	obj.minimum = this.buffer.readBytesAsNumber(4);
	return obj;
    case RR_TYPE_FH:
	var obj = new Object();
	obj.priority = this.buffer.readBytesAsNumber(2);
	obj.weight = this.buffer.readBytesAsNumber(2);
	var name_ccnb = this.buffer.readBytes(rdlength - 4);
	obj.hint = ndn.Name.parse(name_ccnb);
	return obj;
    case RR_TYPE_NEXISTS:
	return {};
    case RR_TYPE_NDNCERT:
	var obj = new Object();
	var co_ccnb = this.buffer.readBytes(rdlength);
	obj.cert = ndn.ContentObject.parse(co_ccnb);
	return obj;
    case RR_TYPE_NDNCERTSEQ:
	var obj = new Object();
	var name_ccnb = this.buffer.readBytes(rdlength);
	obj.seq = ndn.Name.parse(name_ccnb);
	return obj;
    case RR_TYPE_NDNAUTH:
	var obj = new Object();
	var name_ccnb = this.buffer.readBytes(rdlength);
	obj.zoneName = ndn.Name.parse(name_ccnb);
	return obj;
    default:
	throw new Error("Unknown DNS RR type: " + type);
    }
};

DnsParser.prototype.parseRR = function () {
    var obj = new Object();
    obj.name = this.parseDomainName();
    obj.type = this.buffer.readBytesAsNumber(2);
    obj.clss = this.buffer.readBytesAsNumber(2);  // class is a keyword reserved by JavaScript :(
    obj.ttl = this.buffer.readBytesAsNumber(4);
    obj.rdlength = this.buffer.readBytesAsNumber(2);
    obj.rdata = this.parseRData(obj.type, obj.clss, obj.rdlength);
    return obj;
};

var DNS_SECTION_THRESHOLD = 10;

DnsParser.prototype.parse = function () {
    // Read header
    this.parseHeader();

    if (this.packet.header.qdcount > DNS_SECTION_THRESHOLD || this.packet.header.ancount > DNS_SECTION_THRESHOLD 
	|| this.packet.header.nscount > DNS_SECTION_THRESHOLD || this.packet.header.arcount > DNS_SECTION_THRESHOLD)
	throw new Error('Too many sections in the DNS packet. Stop parsing.');
    
    // Read question section
    for (var i = 0; i < this.packet.header.qdcount; i++) {
	this.packet.question[i] = this.parseQuestion();
    }

    // Read answer section
    for (var i = 0; i < this.packet.header.ancount; i++) {
	this.packet.answer[i] = this.parseRR();
    }

    // Read authority section
    for (var i = 0; i < this.packet.header.nscount; i++) {
	this.packet.authority[i] = this.parseRR();
    }

    // Read additional section
    for (var i = 0; i < this.packet.header.arcount; i++) {
	this.packet.additional[i] = this.parseRR();
    }

    return this.packet;
};

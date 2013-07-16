var BufferIterator = function BufferIterator(/*Buffer*/ buf) {
    this.buffer = buf;
    this.length = buf.length;
    this.offset = 0;
};

exports.BufferIterator = BufferIterator;

/**
 * Read a sequence of bytes and return a Buffer object containing these bytes.
 * Advance the offset by 'length' bytes after reading.
 * @param {number} length The number of bytes to read.
 * @returns {Buffer}
 */
BufferIterator.prototype.readBytes = function (length) {
    var tmp = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return tmp;
};


/**
 * Read a sequence of bytes and return a string converted from that sequence.
 * Advance the offset by 'length' bytes after reading.
 * @param {number} length The number of bytes to read.
 * @returns {string}
 */
BufferIterator.prototype.readBytesAsString = function (length) {
    return this.readBytes(length).toString('ascii');
};


/**
 * Read a sequence of bytes and return an unsigned integer converted from that sequence.
 * Advance the offset by 'length' bytes after reading.
 * Currently the length is limited to be less than 4 (32 bits) in order to avoid overflow in JavaScript.
 * @param {number} length The number of bytes to read.
 * @returns {number}
 */
BufferIterator.prototype.readBytesAsNumber = function (length) {
    if (length > 4)
	return null; // number overflow
    
    return parseInt(this.readBytes(length).toString('hex'), 16);
};

/**
 * Read one byte without advancing the internal offset.
 * @returns {number}
 */
BufferIterator.prototype.peek = function () {
    return this.buffer[this.offset];
};


BufferIterator.prototype.seek = function (offset) {
    this.offset = offset;
};

BufferIterator.prototype.advance = function (step) {
    this.offset += step;
};

BufferIterator.prototype.endOfBuffer = function () {
    return this.offset == this.buffer.length;
};

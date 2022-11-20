#include <include/TCP/CircularBuffer.h>

TCPCircularBuffer::TCPCircularBuffer(int size) : data(size), start(1), next(1), last(0) {}

uint32_t TCPCircularBuffer::getStart() {
    return start;
}

uint32_t TCPCircularBuffer::getNext() {
    return next;
}

uint32_t TCPCircularBuffer::getLast() {
    return last;
}

void TCPCircularBuffer::setStart(int n) {
    start = n;
}

void TCPCircularBuffer::setNext(int n) {
    next = n;
}

void TCPCircularBuffer::setLast(int n) {
    last = n;
}

void TCPCircularBuffer::initializeWith(int n) {
    start = n + 1;
    next = n + 1;
    last = n;
}

// Read only from start
int read(int numBytes, std::string& buf) {
    int insertPos = 0;
    while (start != next && insertPos < numBytes) {
        buf[insertPos] = data[start % data.capacity()];
        start++;
        insertPos++;
    }
    return insertPos;
}

// Write to any position (allows us to receive packets out of order)
int write(int numBytes, std::string& buf, int pos) {
    int numWritten = 0;
    while (pos < data.capacity() && pos < buf.size()) {
        data[pos % data.capacity()] = buf[numWritten];
        pos++;
        numWritten++;
    }
    return numWritten;
}

int getNumBytes(int numBytes, std::string& buf) {
    int tempNext = start;
    int pos = 0;
    while (tempNext != (last + 1) && pos < numBytes) {
        buf[pos] = data[tempNext % data.capacity()];
        tempNext++;
        pos++;
    }
    next = tempNext;
    return pos;
}

int getWindowSize() {
    int afterLast = last + 1;
    if (start == afterLast) {
        return data.capacity();
    } else if (start > afterLast) {
        return start - afterLast;
    } else {
        return data.capacity() - (afterLast - start);
    }
}

int getCapacity() {
    return data.capacity();
}

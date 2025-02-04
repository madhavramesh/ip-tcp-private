#include <include/TCP/CircularBuffer.h>
#include <iostream>

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
int TCPCircularBuffer::read(int numBytes, std::string& buf) {
    int bytesRead = 0;
    while (start != next && bytesRead < numBytes) {
        buf.push_back(data[start % data.capacity()]);
        start++;
        bytesRead++;
    }
    return bytesRead;
}

// Write numBytes starting from next position
int TCPCircularBuffer::write(int numBytes, std::string& buf) {
    int numWritten = 0;
    while ((next != last + 1) && (numWritten < numBytes)) {
        data[next % data.capacity()] = buf[numWritten];
        next++;
        numWritten++;
    }
    return numWritten;
}

int TCPCircularBuffer::getWindowSize() {
    int afterLast = last + 1;
    if (start == afterLast) {
        return data.capacity();
    } else {
        return data.capacity() - (afterLast - start);
    }
}

int TCPCircularBuffer::getCapacity() {
    return data.capacity();
}

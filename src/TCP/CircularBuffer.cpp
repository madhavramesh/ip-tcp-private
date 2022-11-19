#include <include/TCP/CircularBuffer.h>

TCPCircularBuffer::TCPCircularBuffer(int size) : data(size), start(1), next(0), last(0) {} // #todo double check initial vals and places where you use it

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
    next = n;
    last = n;
}

int write(int numBytes, std::string& buf) {
    int pos = 0;
    while (last != start && pos < numBytes) {
        last++;
        data[last % data.capacity()] = buf[pos];
        pos++;
    }
    return pos;
}

int read(int numBytes, std::string& buf) {
    int insertPos = 0;
    while (start != next && insertPos < numBytes) {
        buf[insertPos] = data[start % data.capacity()];
        start++;
        insertPos++;
    }
    return insertPos;
}

int put(int numBytes, std::string& buf) {
    int pos = 0;
    while (last - start < data.capacity()) {
        data[next % data.capacity()] = buf[pos];
        pos++;
    }
    return pos;
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

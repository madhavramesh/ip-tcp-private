#include <include/TCP/CircularBuffer.h>

TCPCircularBuffer::TCPCircularBuffer(int size) : data(size), start(1), middle(1), end(0) {}

TCPCircularBuffer::getStart() {
    return start;
}

TCPCircularBuffer::getNext() {
    return next;
}

TCPCircularBuffer::getLast() {
    return last;
}

TCPCircularBuffer::incrementStart(int n) {
    start += n;
}

TCPCircularBuffer::incrementNext(int n) {
    next += n;
}

TCPCircularBuffer::incrementLast(int n) {
    last += n;
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
        next++;
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

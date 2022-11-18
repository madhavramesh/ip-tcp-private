#include <vector>

#include <include/TCP/CircularBuffer.h>

TCPCircularBuffer::TCPCircularBuffer(int size) : data(size), start(1), middle(1), end(0) {}

TCPCircularBuffer::incrementStart(int n) {
    start += n;
}

TCPCircularBuffer::incrementNext(int n) {
    next += n;
}

TCPCircularBuffer::incrementLast(int n) {
    last += n;
}

int write(int numBytes, std::vector<char>& buf) {
    int pos = 0;
    while (last != start && pos < numBytes) {
        last += 1;
        data[last] = buf[pos];
        pos++;
    }
    return pos;
}

int read(int numBytes, std::vector<char>& buf) {
    int insertPos = 0;
    while (start != next && insertPos < numBytes) {
        buf[insertPos] = data[start];
        start += 1;
        insertPos++;
    }
    return insertPos;
}

int getStartToNext(int numBytes, std::vector<char>& buf) {
    int tempNext = start;
    int pos = 0;
    while (tempNext != (last + 1) && pos < numBytes) {
        buf[pos] = data[tempNext % data.capacity()];
        tempNext += 1;
        pos++;
    }
    next = tempNext;
    return pos;
}

int getWindowSize() {
    int afterLast = (last + 1) % data.capacity();
    if (start == afterLast) {
        return data.capacity();
    } else if (start > afterLast) {
        return start - afterLast;
    } else {
        return data.capacity() - (afterLast - start);
    }
}

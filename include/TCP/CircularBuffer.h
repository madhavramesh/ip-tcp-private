#include <vector>

#include <boost/circular_buffer.hpp>

class TCPCircularBuffer {
    public:
        // Size MUST be greater than 1
        TCPCircularBuffer(int size);

        unsigned int getStart();
        unsigned int getNext();
        unsigned int getLast();

        void incrementStart(int n);
        void incrementNext(int n);
        void incrementLast(int n);

        int read(int numBytes, std::string &buf);
        int write(int numBytes, std::string& buf);
        int put(int numBytes, std::string& buf);
        int getNumBytes(int numBytes, std::string& buf);

        int getWindowSize();
        int getCapacity();

    private:
        boost::circular_buffer<char> data;
        unsigned int start;  // Unacknowledged (send buffer) or next read (recv buffer)
        unsigned int next;   // Next send (send buffer) or next expected (recv buffer)
        unsigned int last;   // Last written (send buffer) or last received (recv buffer)

        /* 
        Sending
              1              2              3
        ---------- START ---------- NXT ----------- LAST
        1 = can be discarded, receiver has taken custody
        2 = bytes in flight
        3 = not yet sent, but have been written to the buffer
        
        Receiving
              1              2              3
        ---------- START ---------- NXT ----------- LAST
        1 = can be discarded, have been read from buffer
        2 = receiver has custody, user has not yet read
        3 = have not been acked (can be out of order)
        */
};

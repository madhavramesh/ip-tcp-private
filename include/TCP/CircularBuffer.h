#include <vector>

#include <boost/circular_buffer.hpp>

class TCPCircularBuffer {
    public:
        // Size MUST be greater than 1
        TCPCircularBuffer(int size);

        void incrementStart(int n);
        void incrementNext(int n);
        void incrementLast(int n);

        int read(int numBytes, std::vector<char> buf);
        int write(int numBytes, std::vector<char> buf);
        int getStartToNext(int numBytes, std::vector<char>& buf);

        int getWindowSize();

    private:
        boost::circular_buffer<char> data;
        int start;  // Unacknowledged (send buffer) or next read (recv buffer)
        int next;   // Next send (send buffer) or next expected (recv buffer)
        int last;   // Last written (send buffer) or last received (recv buffer)
};

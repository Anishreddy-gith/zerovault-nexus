# ADR 0003: Local MongoDB host port

MongoDB is exposed on host port 27018 because port 27017 is already occupied on the development machine; containers continue to use port 27017 internally.

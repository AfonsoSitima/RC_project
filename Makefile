user: user.cpp
	g++ -std=c++17 user.cpp -o user

clean:
	rm -f user

.PHONY: clean

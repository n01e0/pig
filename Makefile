all: pig

pig: src/ Makefile
	cargo build
	rm ./pig
	ln -s ./target/debug/pig ./
	sudo setcap "cap_sys_ptrace+ep" ./target/debug/pig

release: src/ Makefile
	cargo build --release
	rm ./pig
	ln -s ./target/release/pig ./
	sudo setcap "cap_sys_ptrace+ep" ./target/debug/pig

clean: pig
	rm pig


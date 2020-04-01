all: debug

check:
	cargo check

debug: step0
	cargo build

release: step0
	cargo build --release

step0: bearssl-0.6/build/libbearssl.a bearffi/libbearffi.a
	mkdir -p target/debug/deps
	ln -fs ../../../bearssl-0.6/build/libbearssl.a target/debug/deps
	ln -fs ../../../bearffi/libbearffi.a target/debug/deps
	mkdir -p target/release/deps
	ln -fs ../../../bearssl-0.6/build/libbearssl.a target/release/deps
	ln -fs ../../../bearffi/libbearffi.a target/release/deps

bearffi/libbearffi.a: .PHONY
	make -C bearffi

bearssl-0.6/build/libbearssl.a: bearssl-0.6.tar.gz
	tar zxf bearssl-0.6.tar.gz
	make -j 4 -C bearssl-0.6

bearssl-0.6.tar.gz:
	ftp https://bearssl.org/bearssl-0.6.tar.gz


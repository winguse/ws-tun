release:
	cargo build --release
	cross build --target x86_64-unknown-linux-gnu --release
	cross build --target armv7-unknown-linux-gnueabihf --release
	cross build --target mipsel-unknown-linux-musl --release
	scp target/x86_64-unknown-linux-gnu/release/ws-tun g1a:~/
	scp target/x86_64-unknown-linux-gnu/release/ws-tun pongping:~/
	scp target/mipsel-unknown-linux-musl/release/ws-tun root@10.8.8.1:~/
	scp target/armv7-unknown-linux-gnueabihf/release/ws-tun pi@10.8.8.141:~/


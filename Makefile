release:
	cargo build --release
	cross build --target x86_64-unknown-linux-gnu --release
	#cross build --target armv7-unknown-linux-gnueabihf --release
	scp target/x86_64-unknown-linux-gnu/release/ws-tun g1a:~/
	scp target/x86_64-unknown-linux-gnu/release/ws-tun pongping:~/


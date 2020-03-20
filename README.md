# Nord

`nord` is a native & free command line application for NordVPN.
The design philosophy of `nord` is that it is native with no dependencies on a modern distro.

# Installing

1. Clone this repository:
	``` bash
	git clone https://github.com/swsuyj/nord
	```
2. Enter the repository:
	``` bash
	cd nord
	```
3. Make the application executable:
	``` bash
	chmod +x nord
	```
4. Set nord up locally:
	``` bash
	./nord setup
	```
5. Log in:
	``` bash
	nord login
	```
6. Connect:
	``` bash
	nord connect
	```

Type `nord --help` for available commands.
Some useful commands:
- `nord set protocol ...`
- `nord set killswitch ...`
- `nord connect ...` where ... is a valid country code, eg us, uk, au, nz.
- `nord disconnect`


# Known bugs

- Connecting to obfuscated servers is not supported at the moment.
	This is an error on NordVPN's half. They are working on a fix.

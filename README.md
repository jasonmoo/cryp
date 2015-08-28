#cryp

cryp is a small set of encryption/decryption tools to make it easy to encrypt files and command line data.

The goal of this project is to provide a simple way to store secrets in code repositories and
work with sensitive data.

cryp is written using only the [go stdlib](http://golang.org/pkg/). The code is approachable and tested.

##How does it work?

cryp consists of 4 command line programs:

 * `enc` - Reads from `STDIN` and outputs base64 encoded data to `STDOUT`
 * `dec` - Reads base64 encoded data from `STDIN` and outputs decrypted data to `STDOUT`
 * `enc_dir` - Takes a list of directories and recursively encrypts each file found within.
 	* Each file is replaced by an encrypted version of itself. The file name, size, mode,
 	mod time and contents are encrypted as a single payload. The payload is in tar format.
	The encrypted file is named the sha256 hash of it's contents.
 * `dec_dir` - Takes a list of directories and recursively looks for encrypted files and decrypts them.
 	* Each file that has a sha256 hash as the file name is attempted to be decrypted. When contents
 	of the file do not match the hash the process is aborted.

cryp is also presented as a library for developing your own tools with.
Please visit [godocs](https://godoc.org/github.com/jasonmoo/cryp) for complete documentation.

Each program expects `CRYP_KEY` to be set in the environment of the current shell.  It
uses this key to encrypt/decrypt and will fail loudly if it is not present.

	jason@mba ~ enc
	2015/08/27 17:30:49 CRYP_KEY not set in environment

###Examples

	jason@mbp ~ export CRYP_KEY=$MY_WORK_CRYP_KEY

	jason@mbp ~ echo "hi" | enc
	O98uYJbb5Q8ehQO4ckWB9rfEPdM1BAhS/OtLrvPKHPJMI9Tu8QTkjsBk7VGTZIaybbTvun7qrwvpbSh7mRtY7Iwq3Std+fRMGBaIUOI=

	jason@mba ~ echo "hi" | enc | dec
	hi

	# create some secrets
	jason@mba ~ : mkdir secrets
	jason@mba ~ : touch secrets/{this,that,theother}
	jason@mba ~ : find secrets
	secrets
	secrets/that
	secrets/theother
	secrets/this

	# encrypt them
	jason@mba ~ : enc_dir secrets/
	Encrypting secrets/that ... 10.479019ms
	Encrypting secrets/theother ... 1.160841ms
	Encrypting secrets/this ... 1.990103ms

	# see they are encrypted
	jason@mba ~ : find secrets/
	secrets
	secrets/090df7a71a2a0141183e7441ed60b7586f33a4679e1a81d69e68ca1e40751c4a
	secrets/58e264fe56cfe3e9351bb8a76f6f408ecc67db5a7d0efeb4a1e4c9df860fdd7d
	secrets/948d14afcda7775d709691c449724004fc3c73c27a2d736e95fe2a4a6e922328

	# decrypt them
	jason@mba ~ : dec_dir secrets/
	Decrypting secrets/090df7a71a2a0141183e7441ed60b7586f33a4679e1a81d69e68ca1e40751c4a ... 446.787µs
	Decrypting secrets/58e264fe56cfe3e9351bb8a76f6f408ecc67db5a7d0efeb4a1e4c9df860fdd7d ... 195.358µs
	Decrypting secrets/948d14afcda7775d709691c449724004fc3c73c27a2d736e95fe2a4a6e922328 ... 249.634µs

	# see they are decrypted
	jason@mba ~ : find secrets/
	secrets
	secrets/that
	secrets/theother
	secrets/this


##How do I use it?

###Setup

First set your `CRYP_KEY` variable.  It can be any length or even be empty (not recommended):

	# here's a simple way to generate and set a random one
	export CRYP_KEY=$(base64 < /dev/urandom | head -c 128)
	echo -e "\nexport CRYP_KEY='$CRYP_KEY'" >> ~/.profile

	# you can also set it to a password you can remember

**YOU MUST SAVE YOUR `CRYP_KEY` OR YOU WILL NOT BE ABLE TO DECRYPT YOUR DATA**

**^^^SUPER IMPORTANT^^^**


###Install

Go 1.5 is required to build the tools.  Install instructions for go [are here](https://golang.org/doc/install).

	go get -v github.com/jasonmoo/cryp/{enc,dec,enc_dir,dec_dir}

That's it.

##The details of the encryption processes

Encryption uses AES256 CFB encryption with a few extra steps.  The code is clear and readable
and should reflect the following outline:

*Encryption*

1.  Create AES256 key to encrypt with by taking SHA-512/256 checksum of the `CRYP_KEY`.
3.  Gzip generated key + data into single payload. (This ensures small data, or no data, is
present as an encrypted payload)
4.  Encrypt payload using AES256 CFB with generated key

*Decryption*

1.  Create AES256 key to encrypt with by taking SHA-512/256 checksum of the `CRYP_KEY`.
4.  Decrypt payload using AES256 CFB with generated key
3.  Gunzip payload and trim off generated key prefix

## License

This software is released under the MIT License (2015).  As such it is free to use and
do with as you like.  Any data destroyed, maliciously or accidentally, while using this
software is not the responsibility of the author.  Please be careful.


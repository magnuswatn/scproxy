scproxy
===

This is a Buypass compatible smart card proxy. It runs on Mac, Linux and Windows, and allows you to use your Buypass smartcard to sign in to online services (e.g. with ID-porten). It's not made for the additional services (signing) that the original Buypass versions allows.

## Why?

Buypass doesn't have a linux compatible version, and their Mac version seems to use an [HTTP server written in Objective-C that hasn't been updated in 10 years](https://github.com/robbiehanson/CocoaHTTPServer). It also has some other issues, so it's just not something you want running as root on your Mac.


## Installation

### Prerequisites

You need go 1.22.4 or later.

On Linux, you aditionally need PCSC lite. To install on Debian-based distros, run:

```
sudo apt-get install libpcsclite-dev pcscd
```

### Installation

```
go install github.com/magnuswatn/scproxy@latest
scproxy --install
```

This will generate a self-signed TLS certificate, install it into your local truststore and start running scproxy as a service. If you don't want to have it running as a service in the background at all times, you can skip the service creation with `scproxy --install --skip-service`. Then you will need to run `scproxy` whenever you want to use it.

> [!NOTE]
> Service creation is not supported on Windows, so you're on your own there. You should probably use the original version from Buypass on Windows (it is good).


# Attribution

The pcsc parts of this is borrowed from the [piv-go](https://github.com/go-piv/piv-go) project. That code is lisenced under the Apache License, Version 2.0. You can find a copy of the license in [LICENSE](LICENSE).

There are some changes done for this project:
* Use T0 protocol instead of T1 against the smart card.
* Expect the apdu to be a complete byte slice - no formatting or chunking needed.
* Read the pending byte count in the 61XX response from the card, and use it in the GET RESPONSE request.
* Include sw1 and sw2 on successfull responses from the card.
* Reset the card at the end of sessions and transactions, instead of just leaving it.
* Removed FreeBSD and OpenBSD support.

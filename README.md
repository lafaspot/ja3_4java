# JA3 in Java
Java code to profile SSL/TLS clients

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

JA3 is a method for creating SSL/TLS client fingerprints that are easy to produce and can be easily shared for threat intelligence.

This repo includes java library for building the JA3 fingerprint string during SSL negotiation.

JA3 is a specification created and open sourced by Salesforce team [here](https://github.com/salesforce/ja3).

## Install

This is packaged as a java library and can be imported as maven or gradle dependency in your project. There are no special installation instructions.

## Usage

Wrap your SSL engine implementation using the JA3 wrapper and then access the fingerprint after the handshake is completed.

```java
    // SSL Handler Wrapper
    final JA3SSLEngineWrapper ja3Wrapper = new JA3SSLEngineWrapper(sslEngine);
    // Accessing the finger print
    final String ja3ClientSignature = (String) sslSession.getValue(JA3Constants.JA3_FINGERPRINT);
```

## Contribute

Please refer to the [contributing.md](Contributing.md) for information about how to get involved. We welcome issues, questions, and pull requests. Pull Requests are welcome.

## Maintainers

Luis Alves: (lafa at verizonmedia.com)

## License

This project is licensed under the terms of the [Apache 2.0](LICENSE-Apache-2.0) open source license. Please refer to [LICENSE](LICENSE) for the full terms.

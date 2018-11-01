# bip38

[![CircleCI](https://circleci.com/gh/sammy00/bip38.svg?style=svg)](https://circleci.com/gh/sammy00/bip38) 
[![codecov](https://codecov.io/gh/sammy00/bip38/branch/master/graph/badge.svg)](https://codecov.io/gh/sammy00/bip38) 
[![Go Report Card](https://goreportcard.com/badge/github.com/sammy00/bip38)](https://goreportcard.com/report/github.com/sammy00/bip38) 
[![LICENSE](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)  

## Overview  
This project implements the [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) draft. Both the plain (as specified in the [nonec](nonec) package) and EC Multiply (as specified in the [ec](ec) package) version of encryption are implemented.

## Requirement  
+ go-1.11 or above with module support  

## Installation  
```bash
go get github.com/sammy00/bip38
```

## References  
+ [bitcoin/bips/bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)  
+ [bitcoinjs/bip38](https://github.com/bitcoinjs/bip38)  
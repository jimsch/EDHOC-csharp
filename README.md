# EDHOC - An implementation of the EDHOC spec for CoAP in C#

[![Build Status](https://api.travis-ci.org/jimsch/EDHOC-csharp.png)](https://travis-ci.org/jimsch/EDHOC-csharp)
[![NuGet Status](http://img.shields.io/nuget/v/Com.AugustCellars.CoAP.EDHOC?style=flat)](https://www.nuget.org/packages/Com.AugustCellars.CoAP.EDHOC)

The Ephemeral Diffie-Hellman Over COSE (EDHOC)(https://datatracker.ietf.org/doc/draft-selander-ace-cose-ecdhe/)
is a key establishment protocol that is designed to run over the CoAP protocol.  It uses a pair of ephemeral
ECDH keys to establish a traffic key which has forward security relative to the next execution of the protocol.

The protocol can use either a symmetric shared secret or ECDH asymmetric keys (either raw or with certificates)
for the purpose of authenticating the parties involved.

## How to Install

The C# implementation is available in the NuGet Package Gallery under the name [Com.AugustCellars.CoAP.EDHOC](https://www.nuget.org/packages/Com.AugustCellars.CoAP.EDHOC).
To install this library as a NuGet package, enter 'Install-Package Com.AugustCellars.CoAP.EDHOC' in the
NuGet Package Managment Console.

## Documentation

This library defines three different classes:

* EdhocInitiator: This class is used by the initiator of the Edhoc protocol.
* EdhocResponder: This class is used by the responder to the Edhoc protocol.
* EdhocResource: This class uses the EdhocResponder class and implements a standard CoAP resource to respond to requests.

## Copyright

Copyright (c) 2017, Jim Schaad


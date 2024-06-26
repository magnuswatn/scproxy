// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is modified for scproxy.

package main

// https://golang.org/s/generatedcode

// Code generated by errors.py DO NOT EDIT.

var pcscErrMsgs = map[int64]string{
	0x00000000: "no error was encountered",
	0x80100001: "an internal consistency check failed",
	0x80100002: "the action was cancelled by an SCardCancel request",
	0x80100003: "the supplied handle was invalid",
	0x80100004: "one or more of the supplied parameters could not be properly interpreted",
	0x80100005: "registry startup information is missing or invalid",
	0x80100006: "not enough memory available to complete this command",
	0x80100007: "an internal consistency timer has expired",
	0x80100008: "the data buffer to receive returned data is too small for the returned data",
	0x80100009: "the specified reader name is not recognized",
	0x8010000A: "the user-specified timeout value has expired",
	0x8010000B: "the smart card cannot be accessed because of other connections outstanding",
	0x8010000C: "the operation requires a Smart Card, but no Smart Card is currently in the device",
	0x8010000D: "the specified smart card name is not recognized",
	0x8010000E: "the system could not dispose of the media in the requested manner",
	0x8010000F: "the requested protocols are incompatible with the protocol currently in use with the smart card",
	0x80100010: "the reader or smart card is not ready to accept commands",
	0x80100011: "one or more of the supplied parameters values could not be properly interpreted",
	0x80100012: "the action was cancelled by the system, presumably to log off or shut down",
	0x80100013: "an internal communications error has been detected",
	0x80100014: "an internal error has been detected, but the source is unknown",
	0x80100015: "an ATR obtained from the registry is not a valid ATR string",
	0x80100016: "an attempt was made to end a non-existent transaction",
	0x80100017: "the specified reader is not currently available for use",
	0x80100018: "the operation has been aborted to allow the server application to exit",
	0x80100019: "the PCI Receive buffer was too small",
	0x8010001A: "the reader driver does not meet minimal requirements for support",
	0x8010001B: "the reader driver did not produce a unique reader name",
	0x8010001C: "the smart card does not meet minimal requirements for support",
	0x8010001D: "the Smart card resource manager is not running",
	0x8010001E: "the Smart card resource manager has shut down",
	0x8010001F: "an unexpected card error has occurred",
	0x80100020: "no primary provider can be found for the smart card",
	0x80100021: "the requested order of object creation is not supported",
	0x80100023: "the identified directory does not exist in the smart card",
	0x80100024: "the identified file does not exist in the smart card",
	0x80100025: "the supplied path does not represent a smart card directory",
	0x80100026: "the supplied path does not represent a smart card file",
	0x80100027: "access is denied to this file",
	0x80100028: "the smart card does not have enough memory to store the information",
	0x80100029: "there was an error trying to set the smart card file object pointer",
	0x8010002A: "the supplied PIN is incorrect",
	0x8010002B: "an unrecognized error code was returned from a layered component",
	0x8010002C: "the requested certificate does not exist",
	0x8010002D: "the requested certificate could not be obtained",
	0x8010002E: "cannot find a smart card reader",
	0x8010002F: "a communications error with the smart card has been detected. More..",
	0x80100030: "the requested key container does not exist on the smart card",
	0x80100031: "the Smart Card Resource Manager is too busy to complete this operation",
	0x80100065: "the reader cannot communicate with the card, due to ATR string configuration conflicts",
	0x80100066: "the smart card is not responding to a reset",
	0x80100067: "power has been removed from the smart card, so that further communication is not possible",
	0x80100068: "the smart card has been reset, so any shared state information is invalid",
	0x80100069: "the smart card has been removed, so further communication is not possible",
	0x8010006A: "access was denied because of a security violation",
	0x8010006B: "the card cannot be accessed because the wrong PIN was presented",
	0x8010006C: "the card cannot be accessed because the maximum number of PIN entry attempts has been reached",
	0x8010006D: "the end of the smart card file has been reached",
	0x8010006E: "the user pressed \"Cancel\" on a Smart Card Selection Dialog",
	0x8010006F: "no PIN was presented to the smart card",
}

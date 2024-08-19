# Misc-Modbus-Security

Software developed by OTNSS, please visit https://otnss.co.uk to find out more or request official support. Do feel free to post any issues/queries here and I will endeavour to help.

A new standard has been published for a version of Modbus/TCP that uses mTLS to add a layer of security on top: https://modbus.org/docs/MB-TCP-Security-v21_2018-07-24.pdf

This is a proof of concept for a Modbus/TCP Security proxy service, allowing clients that talk the new secure protocol to communicate with legacy Modbus/TCP services that do not support it. 

Client  <--------Modbus/TCP Security -----------> This proxy service <--------Modbus/TCP---------> Backend PLC/device/server/etc

It is intended for use with an internal CA and will trust any certificate created by that CA where the clients common name matches a configured list.
There is no RBAC implemented, all clients can perform any action at present.

// Package api defines the data structure to be used in the request/response
// messages between libnetwork and the remote ipam plugin
package api

import (
	"net"
)

// Response is the basic response structure used in all responses
type Response struct {
	Error string
}

// IsSuccess returns wheter the plugin response is successful
func (r *Response) IsSuccess() bool {
	return r.Error == ""
}

// GetError returns the error from the response, if any.
func (r *Response) GetError() string {
	return r.Error
}

// GetAddressSpacesResponse is the response to the ``get default address spaces`` request message
type GetAddressSpacesResponse struct {
	Response
	LocalDefaultAddressSpace  string
	GlobalDefaultAddressSpace string
}

// RequestPool represents the expected data in a ``request address pool`` request message
type RequestPool struct {
	AddressSpace string
	Pool         string
	SubPool      string
	Options      map[string]string
	V6           bool
}

// RequestPoolRes represents the response message to a ``request address pool`` request
type RequestPoolRes struct {
	Response
	PoolID string
	Pool   *net.IPNet
	Data   map[string]string
}

// ReleasePool represents the expected data in a ``release address pool`` request message
type ReleasePool struct {
	PoolID string
}

// ReleasePoolRes represents the response message to a ``release address pool`` request
type ReleasePoolRes struct {
	Response
}

// RequestAddress represents the expected data in a ``request address`` request message
type RequestAddress struct {
	PoolID  string
	Address net.IP
	Options map[string]string
}

// RequestAddressRes represents the expected data in the response message to a ``request address`` request
type RequestAddressRes struct {
	Response
	Address *net.IPNet
	Data    map[string]string
}

// ReleaseAddress represents the expected data in a ``release address`` request message
type ReleaseAddress struct {
	PoolID  string
	Address net.IP
}

// ReleaseAddressRes represents the response message to a ``release address`` request
type ReleaseAddressRes struct {
	Response
}

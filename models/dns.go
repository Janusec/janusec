/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 15:12
 */

package models

import (
	"github.com/miekg/dns"
)

type DNSDomain struct {
	ID int64 `json:"id,string"`

	// Domain name, such as example.com
	Name string `json:"name"`

	//
	DNSRecords []*DNSRecord `json:"-"`
}

type DNSRecord struct {
	ID int64 `json:"id,string"`

	DNSDomainID int64 `json:"dns_domain_id,string"`

	// Rrtype is github.com/miekg/dns.Type
	// Supported types: A, AAAA, CNAME, MX, TXT, SRV, NS, HTTPS, CAA
	Rrtype dns.Type `json:"rrtype"`

	// Record name
	Name string `json:"name"`

	Value string `json:"value"`

	// TTL seconds, default 3600
	TTL uint32 `json:"ttl"`

	// Auto Dispatched within available gateway nodes, public network only
	// Skip the Value, for Load Balance
	Auto bool `json:"auto"`

	// Marked as internal record
	Internal bool `json:"internal"`
}

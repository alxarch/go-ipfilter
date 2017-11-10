package ipfilter

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
)

var HTTPClient = http.DefaultClient

type IPNumber uint32

type IPv4Filter struct {
	size      int
	index     [256][]IPNumber
	blacklist bool
}

type IPv4FilterMap map[uint32]bool

type IPFilter struct {
	index     map[uint64][]net.IP
	size      int
	blacklist bool
}

func (f *IPFilter) Size() int {
	return f.size
}
func (f *IPv4Filter) Size() int {
	return f.size
}

func ReadURLv4(urlStr string, blacklist bool) (*IPv4Filter, error) {
	if body, err := readURL(urlStr); err != nil {
		return nil, err
	} else {
		defer body.Close()
		return ReadIPv4(body, blacklist)
	}
}
func ReadURL(urlStr string, blacklist bool) (*IPFilter, error) {
	if body, err := readURL(urlStr); err != nil {
		return nil, err
	} else {
		defer body.Close()
		return Read(body, blacklist)
	}
}

func readURL(urlStr string) (io.ReadCloser, error) {
	res, err := HTTPClient.Get(urlStr)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("Failed to load ipfilter from %s (%d): %s", urlStr, res.StatusCode, res.Status)
	}
	return res.Body, nil
}

func ReadIPBlacklist(r io.Reader) (*IPFilter, error) {
	return Read(r, true)
}

func ReadIPWhitelist(r io.Reader) (*IPFilter, error) {
	return Read(r, false)
}

func Read(r io.Reader, blacklist bool) (*IPFilter, error) {
	index := map[uint64][]net.IP{}
	n := 0
	s := bufio.NewScanner(r)
	for s.Scan() {
		addr := s.Text()
		if addr == "" || addr[0] == '#' {
			continue
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		k := Sum64a(ip)
		index[k] = append(index[k], ip)
		n++
	}
	f := &IPFilter{index: index, size: n, blacklist: blacklist}
	f.sortIndex()
	return f, s.Err()
}

func IPBlacklist(ips []string) *IPFilter {
	return Build(ips, true)
}
func IPWhitelist(ips []string) *IPFilter {
	return Build(ips, false)
}
func (f *IPFilter) sortIndex() {
	if f.index == nil {
		return
	}
	for k, ips := range f.index {
		sort.Slice(ips, func(i int, j int) bool {
			return bytes.Compare(ips[i], ips[j]) == -1
		})
		f.index[k] = ips
	}
}
func Build(ips []string, blacklist bool) *IPFilter {
	if ips == nil {
		return nil
	}
	index := map[uint64][]net.IP{}
	n := 0

	for _, addr := range ips {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		k := Sum64a(ip)
		index[k] = append(index[k], ip)
		n++
	}
	f := &IPFilter{index: index, size: n, blacklist: blacklist}
	f.sortIndex()
	return f
}

func (f *IPFilter) MatchIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	k := Sum64a(ip)
	shard := f.index[k]
	start, end := 0, len(shard)
	for end > start {
		pos := start + (end-start)>>1
		v := shard[pos]
		switch bytes.Compare(v, ip) {
		case 1:
			end = pos
		case -1:
			start = pos
		default:
			return !f.blacklist
		}
	}
	return f.blacklist
}

func (f IPFilter) MatchString(addr string) bool {
	return f.MatchIP(ParseIP(addr))

}

func ipshard(ip net.IP) uint8 {
	switch len(ip) {
	case net.IPv4len:
		return (ip[0] ^ ip[3]) | (ip[2] ^ ip[1])
	case net.IPv6len:
		return (ip[12] ^ ip[15]) | (ip[14] ^ ip[13])
	default:
		return 0
	}

}

func ParseIPNumberOnly(addr string) (n IPNumber) {
	if len(addr) == 0 || strings.IndexByte(addr, '.') == -1 {
		return
	}
	ip := net.ParseIP(addr)
	return IPNumberOf(ip)
}

func IPNumberOf(ip net.IP) (n IPNumber) {
	switch len(ip) {
	case net.IPv4len:
		return IPNumber((uint32(ip[0]) << 24) | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]))
	case net.IPv6len:
		return IPNumber((uint32(ip[12]) << 24) | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15]))
	}
	return
}
func ParseIPNumber(addr string) (k uint8, n IPNumber) {
	if len(addr) == 0 || strings.IndexByte(addr, '.') == -1 {
		return
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return
	}
	k = ipshard(ip)
	n = IPNumberOf(ip)
	return

}
func ParseIP(addr string) (ip net.IP) {
	if len(addr) == 0 {
		return
	}
	if ip = net.ParseIP(addr); ip == nil {
		return
	}
	if strings.IndexByte(addr, '.') != -1 {
		ip = ip[12:16]
	}

	return

}

func (f IPv4FilterMap) MatchString(v string) bool {
	return f == nil || f[uint32(ParseIPNumberOnly(v))]
}

func (f IPv4FilterMap) MatchIP(ip net.IP) bool {
	return f == nil || f[uint32(IPNumberOf(ip))]
}

func (f *IPv4Filter) MatchIP(ip net.IP) bool {
	n := IPNumberOf(ip)
	if n == 0 {
		return false
	}
	k := ipshard(ip)
	return f.match(k, n)
}
func (f *IPv4Filter) match(k uint8, n IPNumber) bool {
	shard := f.index[k]
	start, end := 0, len(shard)
	for end > start {
		pos := start + (end-start)>>1
		v := shard[pos]
		switch {
		case v > n:
			end = pos
		case v < n:
			start = pos
		default:
			return !f.blacklist
		}
	}
	return f.blacklist
}

func (f *IPv4Filter) MatchString(v string) bool {
	k, n := ParseIPNumber(v)
	if n == 0 {
		return false
	}
	return f.match(k, n)
}

func (f *IPv4Filter) sortIndex() {
	for i := 0; i < 256; i++ {
		shard := f.index[i]
		sort.Slice(shard, func(i int, j int) bool {
			return shard[i] < shard[j]
		})
	}

}

func ReadIPv4Whitelist(r io.Reader) (*IPv4Filter, error) {
	return ReadIPv4(r, false)
}

func ReadIPv4Blacklist(r io.Reader) (*IPv4Filter, error) {
	return ReadIPv4(r, true)
}

func ReadIPv4(r io.Reader, blacklist bool) (*IPv4Filter, error) {
	index := [256][]IPNumber{}
	s := bufio.NewScanner(r)
	i := 0
	for s.Scan() {
		ip := s.Text()
		if ip == "" || ip[0] == '#' {
			continue
		}
		if k, n := ParseIPNumber(ip); n != 0 {
			i++
			index[k] = append(index[k], n)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	f := &IPv4Filter{index: index, blacklist: blacklist, size: i}

	f.sortIndex()
	return f, nil
}

func IPv4Blacklist(ips []string) (f *IPv4Filter) {
	return BuildIPv4(ips, true)
}

func IPv4Whitelist(ips []string) *IPv4Filter {
	return BuildIPv4(ips, false)
}
func BuildIPv4(ips []string, blacklist bool) *IPv4Filter {
	if ips == nil {
		return nil
	}
	index := [256][]IPNumber{}
	for _, ip := range ips {
		k, n := ParseIPNumber(ip)
		if n != 0 {
			index[k] = append(index[k], n)
		}
	}
	f := &IPv4Filter{index: index, blacklist: blacklist}
	f.sortIndex()
	return f
}

func ReadIPv4Map(r io.Reader) (m IPv4FilterMap, err error) {
	m = make(map[uint32]bool)
	s := bufio.NewScanner(r)
	for s.Scan() {
		ip := s.Text()
		if ip == "" || ip[0] == '#' {
			continue
		}

		if n := ParseIPNumberOnly(ip); n != 0 {
			m[uint32(n)] = true
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return m, nil

}

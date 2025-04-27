package internal

import (
	"net"
	"testing"
)

func TestGeneration(t *testing.T) {
	var ips []*net.IPNet
	ips = append(ips, &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)})
	ips = append(ips, &net.IPNet{IP: net.ParseIP("127.0.0.4"), Mask: net.CIDRMask(30, 32)})
	ips = append(ips, &net.IPNet{IP: net.ParseIP("127.0.0.8"), Mask: net.CIDRMask(30, 32)})

	var trusted []*net.IPNet
	trusted = append(trusted, &net.IPNet{IP: net.ParseIP("127.0.1.0"), Mask: net.CIDRMask(24, 32)})
	trusted = append(trusted, &net.IPNet{IP: net.ParseIP("127.0.2.1"), Mask: net.CIDRMask(32, 32)})

	input := NftablesTemplateInput{
		TableName: "blocktbl",
		Blocklists: []BlocklistInput{
			{Name: "list1", IPs: ips},
			{Name: "list2", IPs: ips},
		},
		Trusted: trusted,
	}

	actual, err := GenerateNftable(input)

	expected := `#!/sbin/nft -f

table inet blocktbl
delete table inet blocktbl

table inet blocktbl {
        counter blackhole { }

        set trusted {
                type ipv4_addr; flags constant, interval;
                elements = {
                        127.0.1.0/24, 
                        127.0.2.1/32
                }
        }

        set list1 {
                type ipv4_addr; flags constant, interval;
                elements = {
                        127.0.0.1/32, 
                        127.0.0.4/30, 
                        127.0.0.8/30
                }
        }

        set list2 {
                type ipv4_addr; flags constant, interval;
                elements = {
                        127.0.0.1/32, 
                        127.0.0.4/30, 
                        127.0.0.8/30
                }
        }

        chain blocktbl_chain {
                type filter hook prerouting priority -300; policy accept;
                ip saddr @trusted accept
                ip daddr @trusted accept

                #ip saddr @list1 counter name "blackhole" log prefix "nftables list1 source dropped:" drop
                #ip daddr @list1 counter name "blackhole" log prefix "nftables list1 destination dropped:" drop
                ip saddr @list1 counter name "blackhole" drop
                ip daddr @list1 counter name "blackhole" drop

                #ip saddr @list2 counter name "blackhole" log prefix "nftables list2 source dropped:" drop
                #ip daddr @list2 counter name "blackhole" log prefix "nftables list2 destination dropped:" drop
                ip saddr @list2 counter name "blackhole" drop
                ip daddr @list2 counter name "blackhole" drop

                accept
        }
}
`

	assertNil(t, err)
	assertEquals(t, expected, actual)
}

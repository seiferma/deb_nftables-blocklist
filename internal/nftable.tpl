#!/sbin/nft -f

table inet {{.TableName}}
delete table inet {{.TableName}}

table inet {{.TableName}} {
        counter blackhole { }

        set trusted {
                type ipv4_addr; flags constant, interval;
                elements = {

                {{- range $index, $element := .Trusted}}
                        {{- if $index}}, {{end}}
                        {{$element.String -}}
                {{end}}
                }
        }

        {{- range .Blocklists}}

        set {{.Name}} {
                type ipv4_addr; flags constant, interval;
                elements = {

                {{- range $index, $element := .IPs}}
                        {{- if $index}}, {{end}}
                        {{$element.String -}}
                {{end}}
                }
        }
        {{- end}}

        chain {{.TableName}}_chain {
                type filter hook prerouting priority -300; policy accept;
                ip saddr @trusted accept
                ip daddr @trusted accept

                {{- range .Blocklists}}

                #ip saddr @{{.Name}} counter name "blackhole" log prefix "nftables {{.Name}} source dropped:" drop
                #ip daddr @{{.Name}} counter name "blackhole" log prefix "nftables {{.Name}} destination dropped:" drop
                ip saddr @{{.Name}} counter name "blackhole" drop
                ip daddr @{{.Name}} counter name "blackhole" drop
                {{- end}}

                accept
        }
}

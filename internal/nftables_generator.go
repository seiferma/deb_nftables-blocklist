package internal

import (
	"bytes"
	"embed"
	"log"
	"net"
	"text/template"
)

//go:embed nftable.tpl
var content embed.FS

type NftablesTemplateInput struct {
	TableName  string
	Blocklists []BlocklistInput
	Trusted    []*net.IPNet
}

type BlocklistInput struct {
	Name string
	IPs  []*net.IPNet
}

func GenerateNftable(input NftablesTemplateInput) (string, error) {
	tpl, err := template.ParseFS(content, "nftable.tpl")
	if err != nil {
		log.Fatalf("Could not parse template: %v", err)
		return "", err
	}

	var buffer bytes.Buffer
	err = tpl.Execute(&buffer, input)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

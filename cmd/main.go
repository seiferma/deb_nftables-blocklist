package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/seiferma/nftables-blocklist/internal"
)

type multiStringArgument []string

func (i *multiStringArgument) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *multiStringArgument) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type parsedArgs struct {
	TableName      string
	OutputFileName string
	BlocklistNames []string
	WhitelistNets  []*net.IPNet
}

func parseArgs() parsedArgs {
	// definitions
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "The application creates nftable filters based on firehol blocklists.\nUsage of %s:\n", os.Args[0])
		flag.CommandLine.PrintDefaults()
	}

	var whitelistedNetArgs multiStringArgument
	var blocklistNameArgs multiStringArgument

	flag.Var(&blocklistNameArgs, "b", "name of blocklist to use (can be used multiple times)")
	flag.Var(&whitelistedNetArgs, "w", "whitelisted networks / IP addresses (can be used multiple times)")
	tableName := flag.String("t", "blocklist-firehol", "the name of the table containing the blocklist rules")
	outputFile := flag.String("o", "", "redirect output (generated nftable script) to file")

	// parsing
	flag.Parse()

	// validation (optional/required arguments)
	if len(blocklistNameArgs) < 1 {
		log.Fatalln("You must specify at least one blocklist.")
	}

	// validation (output file is either empty or has content)
	if len(strings.TrimSpace(*outputFile)) < 1 {
		*outputFile = ""
	}

	// validation (blocklist names not empty)
	for _, value := range blocklistNameArgs {
		if len(strings.TrimSpace(value)) < 1 {
			log.Fatalln("All blocklist names must be non-empty")
		}
	}

	// validation (whitelist contains networks or IP addresses)
	whitelistedNets := make([]*net.IPNet, len(whitelistedNetArgs))
	for index, value := range whitelistedNetArgs {
		net, err := internal.ParseIpNet(value)
		if err != nil {
			log.Fatalf("The given whitelisted network \"%v\" is neither an IP nor a network: %v", value, err)
		}
		whitelistedNets[index] = net
	}

	// return parsing result
	return parsedArgs{
		TableName:      *tableName,
		OutputFileName: *outputFile,
		WhitelistNets:  whitelistedNets,
		BlocklistNames: blocklistNameArgs,
	}
}

func generateNftable(args parsedArgs) (string, error) {
	api := internal.FireholeApi{
		UrlPrefix: "https://iplists.firehol.org",
	}

	generationInput := internal.NftablesTemplateInput{
		TableName: args.TableName,
		Trusted:   args.WhitelistNets,
	}

	for _, value := range args.BlocklistNames {
		details, err := api.GetBlocklistDetailsByName(value)
		if err != nil {
			return "", fmt.Errorf("the blocklist \"%v\" could not be loaded: %w", value, err)
		}
		ips, err := api.GetBlocklistIpsByDetails(details)
		if err != nil {
			return "", fmt.Errorf("the blocklist \"%v\" could not be loaded: %w", value, err)
		}
		generationInput.Blocklists = append(generationInput.Blocklists, internal.BlocklistInput{Name: value, IPs: ips})
	}

	content, err := internal.GenerateNftable(generationInput)
	if err != nil {
		return "", fmt.Errorf("could not generate nftable: %w", err)
	}

	return content, nil
}

func main() {
	args := parseArgs()

	content, err := generateNftable(args)
	if err != nil {
		log.Fatal(err)
	}

	if args.OutputFileName == "" {
		fmt.Print(content)
	} else {
		err := os.WriteFile(args.OutputFileName, []byte(content), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

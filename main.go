package main

import (
	"context"
	"encoding/json"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/ovh/cds/contrib/grpcplugins"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/grpcplugin/actionplugin"
	"io/ioutil"
)

type securityCheckerParserActionPlugin struct {
	actionplugin.Common
}

func (actPlugin *securityCheckerParserActionPlugin) Manifest(ctx context.Context, _ *empty.Empty) (*actionplugin.ActionPluginManifest, error) {
	return &actionplugin.ActionPluginManifest{
		Name:        "plugin-security-checker-parser",
		Author:      "Maarten de Boer <maarten@cloudstek.nl>",
		Description: "This is a plugin to parse a sensiolabs/security-checker report",
		Version:     "1.0.0",
	}, nil
}

func (actPlugin *securityCheckerParserActionPlugin) Run(ctx context.Context, q *actionplugin.ActionQuery) (*actionplugin.ActionResult, error) {
	// Get file parameter
	file := q.GetOptions()["file"]
	if file == "" {
		return actionplugin.Fail("File parameter must not be empty")
	}

	// Read file
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return actionplugin.Fail("Unable to read file %s: %v", file, err)
	}

	// Parse file
	var securityCheckerResult map[string]vulnerablePackage
	if err := json.Unmarshal(b, &securityCheckerResult); err != nil {
		return actionplugin.Fail("Unable to read security-checker report: %v", err)
	}

	var report sdk.VulnerabilityWorkerReport

	for n, p := range securityCheckerResult {
		for _, a := range p.advisories {
			v := sdk.Vulnerability{
				Title:     a.title,
				Component: n,
				CVE:       a.cve,
				Link:      a.link,
				Version:   p.version,
			}

			report.Vulnerabilities = append(report.Vulnerabilities, v)
		}
	}

	report.Type = "composer"

	if err := grpcplugins.SendVulnerabilityReport(actPlugin.HTTPPort, report); err != nil {
		return actionplugin.Fail("Unable to send report: %s", err)
	}

	return &actionplugin.ActionResult{
		Status: sdk.StatusSuccess,
	}, nil
}

func main() {
	actPlugin := securityCheckerParserActionPlugin{}
	if err := actionplugin.Start(context.Background(), &actPlugin); err != nil {
		panic(err)
	}
	return
}

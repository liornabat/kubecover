package trivy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ClusterReport struct {
	ReportID    string                        `json:"reportID"`
	ReportDate  time.Time                     `json:"reportDate"`
	ClusterName string                        `json:"clusterName"`
	ScanType    string                        `json:"scanType"`
	ReportItems map[string]*ClusterReportItem `json:"reportItems"`
}

func NewClusterReport() *ClusterReport {
	return &ClusterReport{
		ReportID:    uuid.New().String(),
		ReportDate:  time.Now().UTC(),
		ClusterName: "",
		ScanType:    "k8s",
		ReportItems: make(map[string]*ClusterReportItem),
	}
}

func (c *ClusterReport) ImportClusterDTO(clusterDTO *ClusterDTO, scanType string, scanDate time.Time) *ClusterReport {
	c.ClusterName = clusterDTO.ClusterName
	if !scanDate.IsZero() {
		c.ReportDate = scanDate
	}
	if scanType != "" {
		c.ScanType = "k8s"
	}

	for _, vulnerability := range clusterDTO.Vulnerabilities {
		item, ok := c.ReportItems[vulnerability.Key()]
		if !ok {
			item = NewClusterReportItem(c.ReportID, c.ReportDate, c.ClusterName, c.ScanType).
				SetNamespace(vulnerability.Namespace).
				SetKind(vulnerability.Kind).
				SetName(vulnerability.Name)
			c.ReportItems[vulnerability.Key()] = item
		}
		item.SetError(vulnerability.Error)

		for _, result := range vulnerability.Results {
			if len(result.Vulnerabilities) > 0 {
				for _, vuln := range result.Vulnerabilities {
					itemVulnerability := NewClusterReportItemVulnerabilities().
						SetTarget(result.Target).
						SetClass(result.Class).
						SetType(result.Type).
						SetVulnerabilityID(vuln.VulnerabilityID).
						SetPkgName(vuln.PkgName).
						SetPkgPath(vuln.PkgPath).
						SetDescription(cleanNewLines(vuln.Description)).
						SetSeverity(vuln.Severity).
						SetPkgID(vuln.PkgID).
						SetFixedVersion(vuln.FixedVersion).
						SetTitle(cleanNewLines(vuln.Title)).
						SetReferences(vuln.References).
						SetPrimaryURL(vuln.PrimaryURL).
						SetSeveritySource(vuln.SeveritySource).
						SetLastModifiedDate(vuln.LastModifiedDate).
						SetPublishedDate(vuln.PublishedDate).
						SetInstalledVersion(vuln.InstalledVersion)
					item.AddVulnerability(itemVulnerability)
				}
			}
			for _, secret := range result.Secrets {
				item.AddSecret(NewClusterReportItemSecrets().
					SetTarget(result.Target).
					SetClass(result.Class).
					SetType(result.Type).
					SetTitle(cleanNewLines(secret.Title)).
					SetSeverity(secret.Severity).
					SetCategory(secret.Category).
					SetRuleID(secret.RuleID).
					SetEndLine(secret.EndLine).
					SetStartLine(secret.StartLine))
			}
		}
	}
	for _, misconfiguration := range clusterDTO.Misconfigurations {
		item, ok := c.ReportItems[misconfiguration.Key()]
		if !ok {
			item = NewClusterReportItem(c.ReportID, c.ReportDate, c.ClusterName, c.ScanType).
				SetNamespace(misconfiguration.Namespace).
				SetKind(misconfiguration.Kind).
				SetName(misconfiguration.Name)
			c.ReportItems[misconfiguration.Key()] = item
		}
		for _, result := range misconfiguration.Results {
			if len(result.Misconfiguration) > 0 {
				for _, misconf := range result.Misconfiguration {
					itemMisconfiguration := NewClusterReportItemMisconfiguration().
						SetTarget(result.Target).
						SetClass(result.Class).
						SetType(result.Type).
						SetMisconfigurationType(misconf.Type).
						SetID(misconf.ID).
						SetTitle(misconf.Title).
						SetDescription(cleanNewLines(misconf.Description)).
						SetSeverity(misconf.Severity).
						SetReferences(misconf.References).
						SetPrimaryURL(misconf.PrimaryURL).
						SetType(misconf.Type).
						SetAvdid(misconf.Avdid).
						SetResolution(cleanNewLines(misconf.Resolution)).
						SetMessage(cleanNewLines(misconf.Message)).
						SetQuery(cleanNewLines(misconf.Query)).
						SetStatus(misconf.Status).
						SetStartLine(misconf.CauseMetadata.StartLine).
						SetEndLine(misconf.CauseMetadata.EndLine)
					item.AddMisconfiguration(itemMisconfiguration)
				}
			}
		}
	}
	return c
}

func (c *ClusterReport) items() []*ClusterReportItem {
	var items []*ClusterReportItem
	for _, item := range c.ReportItems {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Incidents() > items[j].Incidents()
	})
	return items
}

func (c *ClusterReport) Print() {
	for _, item := range c.items() {
		if item.Incidents() > 0 {
			fmt.Printf("%s,%s,%s,%d,%d,%d\n", item.Namespace, item.Kind, item.Name, len(item.Vulnerabilities), len(item.Misconfigurations), len(item.Secrets))
		}
	}
}

func (c *ClusterReport) ExportJsonL() string {
	var report []string
	for _, item := range c.items() {
		if item.Incidents() > 0 {
			report = append(report, item.ExportJSON())
		}
	}
	return strings.Join(report, "\n")
}

func cleanNewLines(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}

func severityToScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

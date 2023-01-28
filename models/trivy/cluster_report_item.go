package trivy

import (
	"encoding/json"
	"fmt"
	"time"
)

type ClusterReportItem struct {
	ReportId          string                               `json:"ReportId"`
	ReportDate        time.Time                            `json:"ReportDate"`
	ClusterName       string                               `json:"ClusterName"`
	ScanType          string                               `json:"ScanType"`
	Namespace         string                               `json:"Namespace"`
	Kind              string                               `json:"Kind"`
	Name              string                               `json:"Name"`
	Vulnerabilities   []*ClusterReportItemVulnerabilities  `json:"Vulnerabilities"`
	Secrets           []*ClusterReportItemSecrets          `json:"Secrets"`
	Misconfigurations []*ClusterReportItemMisconfiguration `json:"Misconfigurations"`
	Error             string                               `json:"Error"`
}

func NewClusterReportItem(reportId string, reportDate time.Time, clusterName string, scanType string) *ClusterReportItem {
	return &ClusterReportItem{
		ReportId:          reportId,
		ReportDate:        reportDate,
		ClusterName:       clusterName,
		ScanType:          scanType,
		Namespace:         "",
		Kind:              "",
		Name:              "",
		Vulnerabilities:   []*ClusterReportItemVulnerabilities{},
		Secrets:           []*ClusterReportItemSecrets{},
		Misconfigurations: []*ClusterReportItemMisconfiguration{},
	}
}

func (c *ClusterReportItem) SetNamespace(value string) *ClusterReportItem {
	c.Namespace = value
	return c
}

func (c *ClusterReportItem) SetKind(value string) *ClusterReportItem {
	c.Kind = value
	return c
}

func (c *ClusterReportItem) SetName(value string) *ClusterReportItem {
	c.Name = value
	return c
}

func (c *ClusterReportItem) SetError(value string) *ClusterReportItem {
	c.Error = value
	return c
}

func (c *ClusterReportItem) AddVulnerability(v ...*ClusterReportItemVulnerabilities) *ClusterReportItem {
	c.Vulnerabilities = append(c.Vulnerabilities, v...)
	return c
}

func (c *ClusterReportItem) AddSecret(v ...*ClusterReportItemSecrets) *ClusterReportItem {
	c.Secrets = append(c.Secrets, v...)
	return c
}

func (c *ClusterReportItem) AddMisconfiguration(v ...*ClusterReportItemMisconfiguration) *ClusterReportItem {
	c.Misconfigurations = append(c.Misconfigurations, v...)
	return c
}

func (c *ClusterReportItem) Key() string {
	return fmt.Sprintf("%s/%s/%s", c.Namespace, c.Kind, c.Name)
}

func (c *ClusterReportItem) Incidents() int {
	return len(c.Vulnerabilities) + len(c.Secrets) + len(c.Misconfigurations)
}

func (c *ClusterReportItem) HasIncidents() bool {
	return c.Incidents() > 0
}

func (c *ClusterReportItem) HasError() bool {
	return c.Error != ""
}

func (c *ClusterReportItem) HasVulnerabilities() bool {
	return len(c.Vulnerabilities) > 0
}

func (c *ClusterReportItem) ExportJSON() string {
	data, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(data)
}

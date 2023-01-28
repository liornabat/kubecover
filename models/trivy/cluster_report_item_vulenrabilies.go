package trivy

import (
	"time"
)

type ClusterReportItemVulnerabilities struct {
	Target           string    `json:"Target"`
	Class            string    `json:"Class"`
	Type             string    `json:"Type"`
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgID            string    `json:"PkgID"`
	PkgName          string    `json:"PkgName"`
	PkgPath          string    `json:"PkgPath"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion"`
	SeveritySource   string    `json:"SeveritySource"`
	PrimaryURL       string    `json:"PrimaryURL"`
	Title            string    `json:"Title"`
	Description      string    `json:"Description"`
	Severity         string    `json:"Severity"`
	References       string    `json:"References"`
	PublishedDate    time.Time `json:"PublishedDate"`
	LastModifiedDate time.Time `json:"LastModifiedDate"`
}

func NewClusterReportItemVulnerabilities() *ClusterReportItemVulnerabilities {
	return &ClusterReportItemVulnerabilities{}
}

func (c *ClusterReportItemVulnerabilities) SetTarget(Target string) *ClusterReportItemVulnerabilities {
	c.Target = Target
	return c
}

func (c *ClusterReportItemVulnerabilities) SetClass(Class string) *ClusterReportItemVulnerabilities {
	c.Class = Class
	return c
}

func (c *ClusterReportItemVulnerabilities) SetType(Type string) *ClusterReportItemVulnerabilities {
	c.Type = Type
	return c
}

func (c *ClusterReportItemVulnerabilities) SetVulnerabilityID(vulnerabilityID string) *ClusterReportItemVulnerabilities {
	c.VulnerabilityID = vulnerabilityID
	return c
}

func (c *ClusterReportItemVulnerabilities) SetPkgID(pkgID string) *ClusterReportItemVulnerabilities {
	c.PkgID = pkgID
	return c
}

func (c *ClusterReportItemVulnerabilities) SetPkgName(pkgName string) *ClusterReportItemVulnerabilities {
	c.PkgName = pkgName
	return c
}

func (c *ClusterReportItemVulnerabilities) SetPkgPath(pkgPath string) *ClusterReportItemVulnerabilities {
	c.PkgPath = pkgPath
	return c
}

func (c *ClusterReportItemVulnerabilities) SetSeveritySource(severitySource string) *ClusterReportItemVulnerabilities {
	c.SeveritySource = severitySource
	return c
}

func (c *ClusterReportItemVulnerabilities) SetPrimaryURL(primaryURL string) *ClusterReportItemVulnerabilities {
	c.PrimaryURL = primaryURL
	return c
}

func (c *ClusterReportItemVulnerabilities) SetTitle(title string) *ClusterReportItemVulnerabilities {
	c.Title = title
	return c
}

func (c *ClusterReportItemVulnerabilities) SetDescription(description string) *ClusterReportItemVulnerabilities {
	c.Description = description
	return c
}

func (c *ClusterReportItemVulnerabilities) SetSeverity(severity string) *ClusterReportItemVulnerabilities {
	c.Severity = severity
	return c
}

func (c *ClusterReportItemVulnerabilities) SetReferences(references []string) *ClusterReportItemVulnerabilities {
	if len(references) > 0 {
		c.References = references[0]
	}
	return c
}

func (c *ClusterReportItemVulnerabilities) SetPublishedDate(publishedDate time.Time) *ClusterReportItemVulnerabilities {
	c.PublishedDate = publishedDate
	return c
}

func (c *ClusterReportItemVulnerabilities) SetLastModifiedDate(lastModifiedDate time.Time) *ClusterReportItemVulnerabilities {
	c.LastModifiedDate = lastModifiedDate
	return c
}

func (c *ClusterReportItemVulnerabilities) SetInstalledVersion(installedVersion string) *ClusterReportItemVulnerabilities {
	c.InstalledVersion = installedVersion
	return c
}

func (c *ClusterReportItemVulnerabilities) SetFixedVersion(fixedVersion string) *ClusterReportItemVulnerabilities {
	c.FixedVersion = fixedVersion
	return c
}

func (c *ClusterReportItemVulnerabilities) GetVulnerabilityID() string {
	return c.VulnerabilityID
}

func (c *ClusterReportItemVulnerabilities) CSVHeader() []string {
	return []string{"VulnerabilityID", "Severity", "PkgID", "PkgName", "PkgPath", "InstalledVersion", "FixedVersion", "Title", "Description", "SeveritySource", "PrimaryURL", "References", "PublishedDate", "LastModifiedDate"}
}

func (c *ClusterReportItemVulnerabilities) CSVRecord() []string {
	return []string{c.VulnerabilityID, c.Severity, c.PkgID, c.PkgName, c.PkgPath, c.InstalledVersion, c.FixedVersion, c.Title, c.Description, c.SeveritySource, c.PrimaryURL, c.References, c.PublishedDate.Format("2006-01-02"), c.LastModifiedDate.Format("2006-01-02")}
}

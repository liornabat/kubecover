package trivy

import "strconv"

type ClusterReportItemSecrets struct {
	Target    string `json:"Target"`
	Class     string `json:"Class"`
	Type      string `json:"Type"`
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

func NewClusterReportItemSecrets() *ClusterReportItemSecrets {
	return &ClusterReportItemSecrets{}
}

func (c *ClusterReportItemSecrets) SetTarget(Target string) *ClusterReportItemSecrets {
	c.Target = Target
	return c
}

func (c *ClusterReportItemSecrets) SetClass(Class string) *ClusterReportItemSecrets {
	c.Class = Class
	return c
}

func (c *ClusterReportItemSecrets) SetType(Type string) *ClusterReportItemSecrets {
	c.Type = Type
	return c
}

func (c *ClusterReportItemSecrets) SetRuleID(value string) *ClusterReportItemSecrets {
	c.RuleID = value
	return c
}

func (c *ClusterReportItemSecrets) SetCategory(value string) *ClusterReportItemSecrets {
	c.Category = value
	return c
}

func (c *ClusterReportItemSecrets) SetSeverity(value string) *ClusterReportItemSecrets {
	c.Severity = value
	return c
}

func (c *ClusterReportItemSecrets) SetTitle(value string) *ClusterReportItemSecrets {
	c.Title = value
	return c
}

func (c *ClusterReportItemSecrets) SetStartLine(value int) *ClusterReportItemSecrets {
	c.StartLine = value
	return c
}

func (c *ClusterReportItemSecrets) SetEndLine(value int) *ClusterReportItemSecrets {
	c.EndLine = value
	return c
}

func (c *ClusterReportItemSecrets) CSVHeader() []string {
	return []string{"RuleID", "Category", "Severity", "Title", "StartLine", "EndLine"}
}

func (c *ClusterReportItemSecrets) CSVRecord() []string {
	return []string{c.RuleID, c.Category, c.Severity, c.Title, strconv.Itoa(c.StartLine), strconv.Itoa(c.EndLine)}
}

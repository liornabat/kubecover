package trivy

import (
	"fmt"
	"time"
)

type ClusterDTO struct {
	ClusterName       string                         `json:"ClusterName"`
	Vulnerabilities   []*ClusterVulnerabilityDTO     `json:"Vulnerabilities"`
	Misconfigurations []*ClusterMisconfigurationsDTO `json:"Misconfigurations"`
}

type ClusterVulnerabilityDTO struct {
	Namespace string `json:"Namespace"`
	Kind      string `json:"Kind"`
	Name      string `json:"Name"`
	Results   []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type,omitempty"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgID            string `json:"PkgID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			Layer            struct {
				Digest string `json:"Digest"`
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
			SeveritySource string `json:"SeveritySource"`
			PrimaryURL     string `json:"PrimaryURL"`
			DataSource     struct {
				ID   string `json:"ID"`
				Name string `json:"Name"`
				URL  string `json:"URL"`
			} `json:"DataSource"`
			Title       string   `json:"Title"`
			Description string   `json:"Description"`
			Severity    string   `json:"Severity"`
			CweIDs      []string `json:"CweIDs"`
			Cvss        struct {
				Nvd struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
				Redhat struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"redhat"`
			} `json:"CVSS,omitempty"`
			References       []string  `json:"References"`
			PublishedDate    time.Time `json:"PublishedDate"`
			LastModifiedDate time.Time `json:"LastModifiedDate"`
			VendorIDs        []string  `json:"VendorIDs"`
			FixedVersion     string    `json:"FixedVersion"`
			Cvss0            struct {
				Nvd struct {
					V2Vector string  `json:"V2Vector"`
					V3Vector string  `json:"V3Vector"`
					V2Score  float64 `json:"V2Score"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
			} `json:"CVSS,omitempty"`
			Cvss1 struct {
				Nvd struct {
					V2Vector string  `json:"V2Vector"`
					V3Vector string  `json:"V3Vector"`
					V2Score  int     `json:"V2Score"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
			} `json:"CVSS,omitempty"`
			Cvss2 struct {
				Ghsa struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"ghsa"`
				Nvd struct {
					V2Vector string  `json:"V2Vector"`
					V3Vector string  `json:"V3Vector"`
					V2Score  int     `json:"V2Score"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
				Redhat struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"redhat"`
			} `json:"CVSS,omitempty"`
			Cvss3 struct {
				Ghsa struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"ghsa"`
				Nvd struct {
					V2Vector string  `json:"V2Vector"`
					V3Vector string  `json:"V3Vector"`
					V2Score  int     `json:"V2Score"`
					V3Score  float64 `json:"V3Score"`
				} `json:"nvd"`
				Redhat struct {
					V3Vector string  `json:"V3Vector"`
					V3Score  float64 `json:"V3Score"`
				} `json:"redhat"`
			} `json:"CVSS,omitempty"`
		} `json:"Vulnerabilities,omitempty"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Code      struct {
				Lines []struct {
					Number      int    `json:"Number"`
					Content     string `json:"Content"`
					IsCause     bool   `json:"IsCause"`
					Annotation  string `json:"Annotation"`
					Truncated   bool   `json:"Truncated"`
					Highlighted string `json:"Highlighted"`
					FirstCause  bool   `json:"FirstCause"`
					LastCause   bool   `json:"LastCause"`
				} `json:"Lines"`
			} `json:"Code"`
			Match string `json:"Match"`
			Layer struct {
				Digest    string `json:"Digest"`
				DiffID    string `json:"DiffID"`
				CreatedBy string `json:"CreatedBy"`
			} `json:"Layer"`
		} `json:"Secrets,omitempty"`
		Licenses []struct {
			Severity   string `json:"Severity"`
			Category   string `json:"Category"`
			PkgName    string `json:"PkgName"`
			FilePath   string `json:"FilePath"`
			Name       string `json:"Name"`
			Confidence int    `json:"Confidence"`
			Link       string `json:"Link"`
		} `json:"Licenses,omitempty"`
	} `json:"Results,omitempty"`
	Error string `json:"Error,omitempty"`
}

func (c *ClusterVulnerabilityDTO) Key() string {
	return fmt.Sprintf("%s/%s/%s", c.Namespace, c.Kind, c.Name)
}

type ClusterMisconfigurationsDTO struct {
	Namespace string `json:"Namespace,omitempty"`
	Kind      string `json:"Kind"`
	Name      string `json:"Name"`
	Results   []struct {
		Target         string `json:"Target"`
		Class          string `json:"Class"`
		Type           string `json:"Type,omitempty"`
		MisconfSummary struct {
			Successes  int `json:"Successes"`
			Failures   int `json:"Failures"`
			Exceptions int `json:"Exceptions"`
		} `json:"MisconfSummary,omitempty"`
		Misconfiguration []struct {
			Type          string   `json:"Type"`
			ID            string   `json:"ID"`
			Avdid         string   `json:"AVDID"`
			Title         string   `json:"Title"`
			Description   string   `json:"Description"`
			Message       string   `json:"Message"`
			Namespace     string   `json:"Namespace"`
			Query         string   `json:"Query"`
			Resolution    string   `json:"Resolution"`
			Severity      string   `json:"Severity"`
			PrimaryURL    string   `json:"PrimaryURL"`
			References    []string `json:"References"`
			Status        string   `json:"Status"`
			Layer         struct{} `json:"Layer"`
			CauseMetadata struct {
				Provider  string `json:"Provider"`
				Service   string `json:"Service"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
				Code      struct {
					Lines []struct {
						Number     int    `json:"Number"`
						Content    string `json:"Content"`
						IsCause    bool   `json:"IsCause"`
						Annotation string `json:"Annotation"`
						Truncated  bool   `json:"Truncated"`
						FirstCause bool   `json:"FirstCause"`
						LastCause  bool   `json:"LastCause"`
					} `json:"Lines"`
				} `json:"Code"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func (c *ClusterMisconfigurationsDTO) Key() string {
	return fmt.Sprintf("%s/%s/%s", c.Namespace, c.Kind, c.Name)
}

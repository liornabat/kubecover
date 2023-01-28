package trivy

type ClusterReportItemMisconfiguration struct {
	Target               string `json:"Target"`
	Class                string `json:"Class"`
	Type                 string `json:"Type"`
	MisconfigurationType string `json:"MisconfigurationType"`
	ID                   string `json:"ID"`
	Avdid                string `json:"AVDID"`
	Severity             string `json:"Severity"`
	Title                string `json:"Title"`
	Description          string `json:"Description"`
	Resolution           string `json:"Resolution"`
	Message              string `json:"Message"`
	Namespace            string `json:"Namespace"`
	Query                string `json:"Query"`
	PrimaryURL           string `json:"PrimaryURL"`
	References           string `json:"References"`
	Status               string `json:"Status"`
	StartLine            int    `json:"StartLine"`
	EndLine              int    `json:"EndLine"`
}

func NewClusterReportItemMisconfiguration() *ClusterReportItemMisconfiguration {
	return &ClusterReportItemMisconfiguration{}
}

func (c *ClusterReportItemMisconfiguration) SetTarget(Target string) *ClusterReportItemMisconfiguration {
	c.Target = Target
	return c
}

func (c *ClusterReportItemMisconfiguration) SetClass(Class string) *ClusterReportItemMisconfiguration {
	c.Class = Class
	return c
}

func (c *ClusterReportItemMisconfiguration) SetMisconfigurationType(MisconfigurationType string) *ClusterReportItemMisconfiguration {
	c.MisconfigurationType = MisconfigurationType
	return c
}

func (c *ClusterReportItemMisconfiguration) SetType(Type string) *ClusterReportItemMisconfiguration {
	c.Type = Type
	return c
}

func (c *ClusterReportItemMisconfiguration) SetID(ID string) *ClusterReportItemMisconfiguration {
	c.ID = ID
	return c
}

func (c *ClusterReportItemMisconfiguration) SetAvdid(Avdid string) *ClusterReportItemMisconfiguration {
	c.Avdid = Avdid
	return c
}

func (c *ClusterReportItemMisconfiguration) SetTitle(Title string) *ClusterReportItemMisconfiguration {
	c.Title = Title
	return c
}

func (c *ClusterReportItemMisconfiguration) SetDescription(Description string) *ClusterReportItemMisconfiguration {
	c.Description = Description
	return c
}

func (c *ClusterReportItemMisconfiguration) SetMessage(Message string) *ClusterReportItemMisconfiguration {
	c.Message = Message
	return c
}

func (c *ClusterReportItemMisconfiguration) SetNamespace(Namespace string) *ClusterReportItemMisconfiguration {
	c.Namespace = Namespace
	return c
}

func (c *ClusterReportItemMisconfiguration) SetQuery(Query string) *ClusterReportItemMisconfiguration {
	c.Query = Query
	return c
}

func (c *ClusterReportItemMisconfiguration) SetResolution(Resolution string) *ClusterReportItemMisconfiguration {
	c.Resolution = Resolution
	return c
}

func (c *ClusterReportItemMisconfiguration) SetSeverity(Severity string) *ClusterReportItemMisconfiguration {
	c.Severity = Severity
	return c
}

func (c *ClusterReportItemMisconfiguration) SetPrimaryURL(PrimaryURL string) *ClusterReportItemMisconfiguration {
	c.PrimaryURL = PrimaryURL
	return c
}

func (c *ClusterReportItemMisconfiguration) SetReferences(References []string) *ClusterReportItemMisconfiguration {
	if len(References) > 0 {
		c.References = References[0]
	}
	return c
}

func (c *ClusterReportItemMisconfiguration) SetStatus(Status string) *ClusterReportItemMisconfiguration {
	c.Status = Status
	return c
}

func (c *ClusterReportItemMisconfiguration) SetStartLine(value int) *ClusterReportItemMisconfiguration {
	c.StartLine = value
	return c
}

func (c *ClusterReportItemMisconfiguration) SetEndLine(value int) *ClusterReportItemMisconfiguration {
	c.EndLine = value
	return c
}

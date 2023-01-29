package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/liornabat/kubecover/models/trivy"
)

func main() {
	data, err := os.ReadFile("hoocus--design-pack-builder.json")
	if err != nil {
		panic(err)
	}
	clusterDto := &trivy.ClusterDTO{}
	err = json.Unmarshal(data, clusterDto)
	if err != nil {
		panic(err)
	}
	reportDate, err := time.Parse("2006-01-02", "2023-01-29")
	if err != nil {
		panic(err)
	}
	clusterReport := trivy.NewClusterReport().ImportClusterDTO(clusterDto, "", reportDate)
	//// clusterReport.Print()
	//err = os.WriteFile("hoocus-vuln.csv", []byte(clusterReport.CSVVulnerabilitiesReport()), 0644)
	//if err != nil {
	//	panic(err)
	//}

	err = os.WriteFile("hoocus--design-pack-builder-jsonl.txt", []byte(clusterReport.ExportJsonL()), 0644)
	if err != nil {
		panic(err)
	}
}

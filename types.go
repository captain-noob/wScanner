package main

type PortScanResult map[string][]string

type ScanResult struct {
    IP      string 
    Port    string    
    Scheme  string 
}

type ScanResultList []ScanResult

type ReconInfo struct {
	CategoryID string
	CategoryName string
	HeaderName string
	HeaderValue string
	Purpose string	
}

type ResponseResult struct {
	TargetData ScanResult
	InitialURI string
	RedirectURi string
	PageTitle string
	StatusCode string
	ContentType string
	Server string
	ContentLength string
	ReconInfo []ReconInfo
}

type ResponseResultList []ResponseResult

type HeaderPurpose struct {
	Purpose string `json:"Purpose"`
	Header  string `json:"header"`
}

type HeaderConfig struct {
	WebServer []HeaderPurpose `json:"web_server"`
	FrameworkRuntime []HeaderPurpose `json:"framework_runtime"`
	CMS []HeaderPurpose `json:"cms"`
	EnterpriseBusinessApps []HeaderPurpose `json:"enterprise_business_apps"`
	AnalyticsMarketingTesting []HeaderPurpose `json:"analytics_marketing_testing"`
	CulturalMisc []HeaderPurpose `json:"cultural_misc"`
	WafSecurity []HeaderPurpose `json:"waf_security"`
	CDNReverseProxyCloud []HeaderPurpose `json:"cdn_reverse_proxy_cloud"`
	CacheOptimization []HeaderPurpose `json:"cache_optimization"`
	HostingPlatform []HeaderPurpose `json:"hosting_platform"`
	ApplicationInternal []HeaderPurpose `json:"application_internal"`
}
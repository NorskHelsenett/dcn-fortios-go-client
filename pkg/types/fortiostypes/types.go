package fortiostypes

type FortigateNamedReference struct {
	Name string `json:"name"`
}

type FortigateAddressGroup struct {
	Name   string                    `json:"name"`
	Color  int                       `json:"color,omitempty"`
	Member []FortigateNamedReference `json:"member"`
}

type FortigateIPv4Address struct {
	Name    string `json:"name"`
	Subnet  string `json:"subnet"`
	Type    string `json:"type"`
	Color   int    `json:"color,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type FortigateIPv6Address struct {
	Name    string `json:"name"`
	Ip6     string `json:"ip6"`
	Type    string `json:"type"`
	Color   int    `json:"color,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type FortigateErrorResponse struct {
	HTTPStatus int    `json:"http_status"`
	Status     string `json:"status"`
	HTTPMethod string `json:"http_method"`
}

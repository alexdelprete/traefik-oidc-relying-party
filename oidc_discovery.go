package traefik_oidc_relying_party

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strconv"
)

type Endpoints struct {
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
	EndSessionEndpoint                 string `json:"end_session_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	KerberosEndpoint                   string `json:"kerberos_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	RegistrationEndpoint               string `json:"registration_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	TokenRevocationEndpoint            string `json:"token_revocation_endpoint"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
}

// OIDCDiscovery represents the discovered OIDC endpoints
type OIDCDiscovery struct {
	AcrValuesSupported                                        []string   `json:"acr_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string   `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string   `json:"authorization_encryption_enc_values_supported"`
	AuthorizationEndpoint                                     string     `json:"authorization_endpoint"`
	AuthorizationSigningAlgValuesSupported                    []string   `json:"authorization_signing_alg_values_supported"`
	BackchannelAuthenticationEndpoint                         string     `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string   `json:"backchannel_authentication_request_signing_alg_values_supported"`
	BackchannelLogoutSessionSupported                         bool       `json:"backchannel_logout_session_supported"`
	BackchannelLogoutSupported                                bool       `json:"backchannel_logout_supported"`
	BackchannelTokenDeliveryModesSupported                    []string   `json:"backchannel_token_delivery_modes_supported"`
	CheckSessionIframe                                        string     `json:"check_session_iframe"`
	ClaimsParameterSupported                                  bool       `json:"claims_parameter_supported"`
	ClaimsSupported                                           []string   `json:"claims_supported"`
	ClaimTypesSupported                                       []string   `json:"claim_types_supported"`
	CloudGraphHostName                                        string     `json:"cloud_graph_host_name"`
	CloudInstanceName                                         string     `json:"cloud_instance_name"`
	CodeChallengeMethodsSupported                             []string   `json:"code_challenge_methods_supported"`
	DeviceAuthorizationEndpoint                               string     `json:"device_authorization_endpoint"`
	DisplayValuesSupported                                    []string   `json:"display_values_supported"`
	EndSessionEndpoint                                        string     `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                        bool       `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                               bool       `json:"frontchannel_logout_supported"`
	GrantTypesSupported                                       []string   `json:"grant_types_supported"`
	HttpLogoutSupported                                       bool       `json:"http_logout_supported"`
	IdTokenEncryptionAlgValuesSupported                       []string   `json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptionEncValuesSupported                       []string   `json:"id_token_encryption_enc_values_supported"`
	IdTokenSigningAlgValuesSupported                          []string   `json:"id_token_signing_alg_values_supported"`
	IntrospectionEndpoint                                     string     `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported                 []string   `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string   `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	Issuer                                                    string     `json:"issuer"`
	JWKSURI                                                   string     `json:"jwks_uri"`
	KerberosEndpoint                                          string     `json:"kerberos_endpoint"`
	MicrosoftGraphHost                                        string     `json:"msgraph_host"`
	MtlsEndpointAliases                                       *Endpoints `json:"mtls_endpoint_aliases"`
	PushedAuthorizationRequestEndpoint                        string     `json:"pushed_authorization_request_endpoint"`
	RbacURL                                                   string     `json:"rbac_url"`
	RegistrationEndpoint                                      string     `json:"registration_endpoint"`
	RequestObjectEncryptionAlgValuesSupported                 []string   `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported                 []string   `json:"request_object_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported                    []string   `json:"request_object_signing_alg_values_supported"`
	RequestParameterSupported                                 bool       `json:"request_parameter_supported"`
	RequestURIParameterSupported                              bool       `json:"request_uri_parameter_supported"`
	RequirePushedAuthorizationRequests                        bool       `json:"require_pushed_authorization_requests"`
	RequireRequestUriRegistration                             bool       `json:"require_request_uri_registration"`
	ResponseModesSupported                                    []string   `json:"response_modes_supported"`
	ResponseTypesSupported                                    []string   `json:"response_types_supported"`
	RevocationEndpoint                                        string     `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string   `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string   `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                                           []string   `json:"scopes_supported"`
	SubjectTypesSupported                                     []string   `json:"subject_types_supported"`
	TenantRegionScope                                         string     `json:"tenant_region_scope"`
	TlsClientCertificateBoundAccessTokens                     bool       `json:"tls_client_certificate_bound_access_tokens"`
	TokenEndpoint                                             string     `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string   `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported                []string   `json:"token_endpoint_auth_signing_alg_values_supported"`
	TokenRevocationEndpoint                                   string     `json:"token_revocation_endpoint"`
	UserinfoEncryptionAlgValuesSupported                      []string   `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported                      []string   `json:"userinfo_encryption_enc_values_supported"`
	UserinfoEndpoint                                          string     `json:"userinfo_endpoint"`
	UserinfoSigningAlgValuesSupported                         []string   `json:"userinfo_signing_alg_values_supported"`

	RawData string
}

// GetOIDCDiscovery retrieves OIDC discovery endpoints from the given OpenID provider
func GetOIDCDiscovery(providerURL string) (*OIDCDiscovery, error) {
	if len(providerURL) <= 0 {
		log("(oidc_discovery) providerURL empty: %s", providerURL)
	} else {
		log("(oidc_discovery) providerURL valid: %s", providerURL)
	}
	requestUrl, err := url.Parse(providerURL)
	if err != nil {
		log("(oidc_discovery) Error parsing providerURL: %s", providerURL)
		return nil, err
	} else {
		log("(oidc_discovery) OK Parsed providerURL: %s", providerURL)
	}

	requestUrl.Path = path.Join(requestUrl.Path, ".well-known/openid-configuration")
	wellKnown := requestUrl.String()

	// Make HTTP GET request to the OpenID provider's discovery endpoint
	resp, err := http.Get(wellKnown)
	if err != nil {
		log("(oidc_discovery) Error http-getting discovery endpoints - StatusCode: %s - Err: %s", strconv.FormatInt(int64(resp.StatusCode), 10), err.Error())
		return nil, err
	} else {
		log("(oidc_discovery) OK http-getting discovery endpoints - URL: %s", wellKnown)
	}
	defer resp.Body.Close()

	// Check if the response status code is successful (2xx)
	if resp.StatusCode >= 300 {
		log("(oidc_discovery) Error http-getting (statuscode) OIDC discovery endpoints. Status code: %s", strconv.FormatInt(int64(resp.StatusCode), 10))
		return nil, err
	} else {
		log("(oidc_discovery) OK http-getting (statuscode) discovery endpoints: %s", wellKnown)
	}

	document := OIDCDiscovery{
		// RawData: string(io.ReadAll(resp.Body)),
	}

	// Decode the JSON response into the OIDCDiscovery struct
	err = json.NewDecoder(resp.Body).Decode(&document)

	if err != nil {
		log("(oidc_discovery) Error json-decoding OIDC discovery endpoints. Status code: %s", err.Error())
		return nil, err
	} else {
		log("(oidc_discovery) OK json-decoding OIDC discovery endpoints.")
	}
	return &document, nil
}

// func main() {
// 	// Replace "https://your-openid-provider" with the actual URL of your OpenID provider
// 	providerURL := "https://your-openid-provider"

// 	// Call the GetOIDCDiscovery function to retrieve OIDC discovery endpoints
// 	discovery, err := GetOIDCDiscovery(providerURL)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	// Print the discovered OIDC endpoints
// 	fmt.Printf("Issuer: %s\n", discovery.Issuer)
// 	fmt.Printf("Authorization Endpoint: %s\n", discovery.AuthorizationEndpoint)
// 	fmt.Printf("Token Endpoint: %s\n", discovery.TokenEndpoint)
// 	fmt.Printf("JWKS URI: %s\n", discovery.JWKSURI)
// }
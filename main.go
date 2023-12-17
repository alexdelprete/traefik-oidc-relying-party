package traefik_oidc_relying_party

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (k *ProviderAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("Authorization")
	if err == nil && strings.HasPrefix(cookie.Value, "Bearer ") {
		token := strings.TrimPrefix(cookie.Value, "Bearer ")
		fmt.Printf("token = %+v\n", token)

		ok, err := k.verifyToken(token)
		fmt.Printf("ok = %+v\n", ok)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			qry := req.URL.Query()
			qry.Del("code")
			qry.Del("state")
			qry.Del("session_state")
			req.URL.RawQuery = qry.Encode()
			req.RequestURI = req.URL.RequestURI()

			expiration := time.Now().Add(-24 * time.Hour)
			newCookie := &http.Cookie{
				Name:    "Authorization",
				Value:   "",
				Path:    "/",
				Expires: expiration,
				MaxAge:  -1,
			}
			http.SetCookie(rw, newCookie)

			k.redirectToProvider(rw, req)
			return
		}
		user, err := extractClaims(token, k.UserClaimName)
		if err == nil {
			req.Header.Set(k.UserHeaderName, user)
		}
		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			fmt.Printf("code is missing, redirect to Provider\n")
			k.redirectToProvider(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			fmt.Printf("state is missing, redirect to Provider\n")
			k.redirectToProvider(rw, req)
			return
		}

		fmt.Printf("exchange auth code called\n")
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		fmt.Printf("exchange auth code finished %+v\n", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(rw, &http.Cookie{
			Name:     "Authorization",
			Value:    "Bearer " + token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})

		qry := req.URL.Query()
		qry.Del("code")
		qry.Del("state")
		qry.Del("session_state")
		req.URL.RawQuery = qry.Encode()
		req.RequestURI = req.URL.RequestURI()

		scheme := req.Header.Get("X-Forwarded-Proto")
		host := req.Header.Get("X-Forwarded-Host")
		originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)
		log("🐸 Redirect originalURL: %s", originalURL)

		http.Redirect(rw, req, originalURL, http.StatusFound)
	}
}

func extractClaims(tokenString string, claimName string) (string, error) {
	jwtContent := strings.Split(tokenString, ".")
	if len(jwtContent) < 3 {
		return "", fmt.Errorf("malformed jwt")
	}

	var jwtClaims map[string]interface{}
	decoder := base64.StdEncoding.WithPadding(base64.NoPadding)

	jwt_bytes, _ := decoder.DecodeString(jwtContent[1])
	if err := json.Unmarshal(jwt_bytes, &jwtClaims); err != nil {
		return "", err
	}

	if claimValue, ok := jwtClaims[claimName]; ok {
		return fmt.Sprintf("%v", claimValue), nil
	}
	return "", fmt.Errorf("missing claim %s", claimName)
}

func (k *ProviderAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}
	log("🐸  TokenEndPoint: %s", k.DiscoveryDoc.TokenEndpoint)

	resp, err := http.PostForm(k.DiscoveryDoc.TokenEndpoint,
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		log("🐸  Error sending AuthorizationCode in POST: %s", err.Error())
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log("🐸  Received bad HTTP response from Provider: %s", string(body))
		return "", err
	}

	var tokenResponse ProviderTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		log("🐸  Error decoding ProviderTokenResponse: %s", err.Error())
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (k *ProviderAuth) redirectToProvider(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	log("🐸  AuthorizationEndPoint: %s", k.DiscoveryDoc.AuthorizationEndpoint)

	redirectURL, err := url.Parse(k.DiscoveryDoc.AuthorizationEndpoint)
	if err != nil {
		log("🐸  Error parsing AuthorizationEndpoint: %s", err.Error())
	}

	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func (k *ProviderAuth) verifyToken(token string) (bool, error) {
	client := &http.Client{}

	data := url.Values{
		"token": {token},
	}

	log("🐸  IntrospectionEndpoint: %s", k.DiscoveryDoc.IntrospectionEndpoint)

	req, err := http.NewRequest(
		http.MethodPost,
		k.DiscoveryDoc.IntrospectionEndpoint,
		strings.NewReader(data.Encode()),
	)

	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		log("🐸  Error after Introspection http request: %s", err.Error())
		return false, err
	} else {
		log("🐸  Introspection http request OK - IntrospectionEndpoint: %s", k.DiscoveryDoc.IntrospectionEndpoint)
	}
	defer resp.Body.Close()

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)

	if err != nil {
		log("🐸  Error decoding response: %s", err.Error())
		return false, err
	} else {
		log("🐸  Response decoding OK - IntrospectionEndpoint: %s", k.DiscoveryDoc.IntrospectionEndpoint)
	}

	return introspectResponse["active"].(bool), nil
}

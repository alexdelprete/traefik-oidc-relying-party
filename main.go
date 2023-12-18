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
		ok, userClaimName, err := k.verifyToken(token)
		if err != nil {
			log("(main) [ERROR] Verifying token: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		} else {
			log("(main) [OK] Token verified: %+v", token)
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
		// set header "X-Forwarded-User" to claim "preferred_username"
		// both header and claim to be used are configurable
		if len(userClaimName) > 0 {
			req.Header.Set(k.UserHeaderName, userClaimName)
			log("(main) [OK] Set http UserHeader: %s to UserClaimName: %s with UserClaimValue: %s", k.UserHeaderName, k.UserClaimName, userClaimName)
		} else {
			log("(main) [ERROR] Claim value not extracted: %s", err.Error())
		}
		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			log("(main) [OK] Code is missing, redirect to Provider")
			k.redirectToProvider(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			log("(main) [OK] State is missing, redirect to Provider")
			k.redirectToProvider(rw, req)
			return
		}

		log("(main) exchange auth code called")
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		log("(main) Exchange Auth Code completed: %+v", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			log("(main) [ERROR] Exchange Auth Code: %s", err.Error())
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
		log("(main) [OK] Redirect originalURL: %s", originalURL)

		http.Redirect(rw, req, originalURL, http.StatusFound)
	}
}

func (k *ProviderAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}
	log("(main) [OK] TokenEndPoint: %s", k.DiscoveryDoc.TokenEndpoint)

	resp, err := http.PostForm(k.DiscoveryDoc.TokenEndpoint,
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"client_secret": {k.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		log("(main) [ERROR] Sending AuthorizationCode in POST: %s", err.Error())
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log("(main) [ERROR] Received bad HTTP response from Provider: %s", string(body))
		return "", err
	}

	var tokenResponse ProviderTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		log("(main) [ERROR] Decoding ProviderTokenResponse: %s", err.Error())
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

	log("(main) [OK] AuthorizationEndPoint: %s", k.DiscoveryDoc.AuthorizationEndpoint)

	redirectURL, err := url.Parse(k.DiscoveryDoc.AuthorizationEndpoint)
	if err != nil {
		log("(main) [ERROR] Parsing AuthorizationEndpoint: %s", err.Error())
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

func (k *ProviderAuth) verifyToken(token string) (bool, string, error) {
	client := &http.Client{}

	data := url.Values{
		"token": {token},
	}

	log("(main) [OK] IntrospectionEndpoint: %s", k.DiscoveryDoc.IntrospectionEndpoint)

	req, err := http.NewRequest(
		http.MethodPost,
		k.DiscoveryDoc.IntrospectionEndpoint,
		strings.NewReader(data.Encode()),
	)

	if err != nil {
		return false, "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		log("(main) [ERROR] After Introspection http request: %s", err.Error())
		return false, "", err
	} else {
		log("(main) [OK] Introspection http request OK - IntrospectionEndpoint: %s", k.DiscoveryDoc.IntrospectionEndpoint)
	}
	defer resp.Body.Close()

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)

	if err != nil {
		log("(main) [ERROR] decoding response: %s", err.Error())
		return false, "", err
	} else {
		log("(main) [OK] Response decoding OK - IntrospectResponse: %+v", introspectResponse)
	}
	log("(main) [OK] IntrospectResponse check return values - introspectResponse[active]: %s - introspectResponse[UserClaimName]: %s", introspectResponse["active"].(string), introspectResponse[k.UserClaimName])
	return introspectResponse["active"].(bool), introspectResponse[k.UserClaimName].(string), nil
}

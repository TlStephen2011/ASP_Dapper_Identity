import {Injectable} from '@angular/core';
import {OAuthService} from 'angular-oauth2-oidc';

@Injectable({
    providedIn: 'root'
})
export class GoogleSigninService {

    constructor(private oauthService: OAuthService) {
        this.configureOAuth();
    }

    configureOAuth() {
        this.oauthService.configure({
            // Your Google OAuth2 credentials and configuration
            clientId: '1029886995860-5m4l2j4kd7u6hnte0qomqbbss2rvnkd0.apps.googleusercontent.com',
            issuer: 'https://accounts.google.com',  // Google's OAuth2 issuer
            redirectUri: window.location.origin + '/home',
            strictDiscoveryDocumentValidation: false,
            scope: 'openid profile email',
            responseType: 'token id_token', // You need the id_token from the response
            showDebugInformation: true, // Enable debug information (optional)
            // Optionally handle validation
            jwks: {
                url: 'https://www.googleapis.com/oauth2/v3/certs' // Google's JWKS endpoint
            },
            sessionChecksEnabled: true,
        });

        this.oauthService.setupAutomaticSilentRefresh();
        this.oauthService.loadDiscoveryDocumentAndTryLogin();
    }

    signInWithGoogle() {
        this.oauthService.initLoginFlow();
    }

    get idToken(): string {
        return this.oauthService.getIdToken();
    }

    get accessToken(): string {
        return this.oauthService.getAccessToken();
    }
}

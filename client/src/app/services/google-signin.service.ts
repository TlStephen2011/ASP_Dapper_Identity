import {Injectable} from '@angular/core';
import {OAuthService} from 'angular-oauth2-oidc';
import {BehaviorSubject, Observable} from 'rxjs';
import {HttpClient} from '@angular/common/http';
import {environment} from '../../environments/environment';

@Injectable({
    providedIn: 'root'
})
export class GoogleSigninService {

    private googleResponseUrl = `${environment.serverUrl}/api/Auth/google-response`;

    private receivedToken = new BehaviorSubject<string>('');
    googleToken$ = this.receivedToken.asObservable();

    constructor(private oauthService: OAuthService, private http: HttpClient) {
        this.configureOAuth();
    }

    configureOAuth() {
        this.oauthService.configure({
            clientId: '1029886995860-5m4l2j4kd7u6hnte0qomqbbss2rvnkd0.apps.googleusercontent.com',
            issuer: 'https://accounts.google.com',
            redirectUri: window.location.origin + '/login',
            strictDiscoveryDocumentValidation: false,
            scope: 'openid profile email',
            responseType: 'token id_token',
            showDebugInformation: true,
            jwks: {
                url: 'https://www.googleapis.com/oauth2/v3/certs'
            },
            sessionChecksEnabled: true,
        });

        this.oauthService.setupAutomaticSilentRefresh();
        this.oauthService.loadDiscoveryDocumentAndTryLogin().then(() => {
            const idToken = this.oauthService.getIdToken();
            if (idToken) {
                this.receivedToken.next(idToken);
            }
        }).catch(e => {
            console.error(e);
        });
    }

    signInWithGoogle() {
        this.oauthService.initLoginFlow();
    }

    handleToken(token: string): Observable<{ jwtToken: string }> {
        return this.http.post<{jwtToken: string}>(this.googleResponseUrl, { idToken: token });
    }

    get idToken(): string {
        return this.oauthService.getIdToken();
    }
}

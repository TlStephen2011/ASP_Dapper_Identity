import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {environment} from '../../environments/environment';
import {Observable} from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class AuthService {

    private loginUrl = `${environment.serverUrl}/api/Auth/login`;

    constructor(private http: HttpClient) {
    }

    signin(username: string, password: string) : Observable<{ jwtToken: string}> {
        return this.http.post<{ jwtToken: string }>(this.loginUrl, {username, password});
    }

    handleToken(jwtToken: string) {
        localStorage.setItem('jwtToken', jwtToken);
    }
}

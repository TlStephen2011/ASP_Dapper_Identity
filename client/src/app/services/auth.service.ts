import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {environment} from '../../environments/environment';

@Injectable({
    providedIn: 'root'
})
export class AuthService {

    private loginUrl = `${environment.serverUrl}/api/Auth/login`;

    constructor(private http: HttpClient) {
    }

    signin(username: string, password: string) {
        console.log(environment);
        return this.http.post(this.loginUrl, {username, password});
    }
}

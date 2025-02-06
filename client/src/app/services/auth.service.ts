import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';

@Injectable({
    providedIn: 'root'
})
export class AuthService {

    private loginUrl = 'https://localhost:5001/api/Auth/login';

    constructor(private http: HttpClient) {
    }

    signin(username: string, password: string) {
        return this.http.post(this.loginUrl, {username, password});
    }
}

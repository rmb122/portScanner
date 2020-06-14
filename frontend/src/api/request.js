import axios from 'axios';

class Request {
    base = 'http://127.0.0.1:8000/api';
    instance;

    constructor() {
        this.instance = axios.create({
            baseURL: this.base,
            timeout: 10000,
            withCredentials: true
        });
    }

    get(path, data = {}, config = {}) {
        return new Promise(async (resolve) => {
            config['params'] = data;
            let res = await this.instance.get(path, config);
            resolve(res)
        })
    }

    post(path, data = {}, config = {}) {
        return new Promise(async (resolve) => {
            let res = await this.instance.post(path, data, config);
            resolve(res);
        })
    }
}

let request = new Request();
export default request;
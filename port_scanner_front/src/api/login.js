import request from "@/api/request";

class Login {
    async status() {
        return await request.get("/status");
    }

    async login(password) {
        return await request.post("/login", {'password': password});
    }
}

let login = new Login();
export default login;